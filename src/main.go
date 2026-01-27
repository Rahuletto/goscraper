package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"goscraper/src/globals"
	"goscraper/src/handlers"
	"goscraper/src/helpers/databases"
	"goscraper/src/types"
	"goscraper/src/utils"
	"log"
	"net"
	"os"

	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cache"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/etag"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/joho/godotenv"
)

func main() {
	if globals.DevMode {
		godotenv.Load()
	}

	app := fiber.New(fiber.Config{
		Prefork:      false,
		ServerHeader: "GoScraper",
		AppName:      "GoScraper v3.0",
		JSONEncoder:  json.Marshal,
		JSONDecoder:  json.Unmarshal,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			return utils.HandleError(c, err)
		},
	})

	app.Use(recover.New())
	app.Use(compress.New(compress.Config{
		Level: compress.LevelBestSpeed,
	}))
	app.Use(etag.New())

	urls := os.Getenv("URL")
	allowedOrigins := "http://localhost:243"
	if urls != "" {
		allowedOrigins += "," + urls
	}

	app.Use(cors.New(cors.Config{
		AllowOrigins:     allowedOrigins,
		AllowMethods:     "GET,POST,PUT,DELETE,OPTIONS",
		AllowHeaders:     "Origin,Content-Type,Accept,X-CSRF-Token,Authorization",
		ExposeHeaders:    "Content-Length",
		AllowCredentials: true,
	}))

	app.Use(limiter.New(limiter.Config{
		Max:        25,
		Expiration: 1 * time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			token := c.Get("X-CSRF-Token")
			if token != "" {
				return utils.Encode(token)
			}
			return c.IP()
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "🔨 SHUT UP! Rate limit exceeded. Please try again later.",
			})
		},
		SkipFailedRequests: false,
		LimiterMiddleware:  limiter.SlidingWindow{},
	}))

	app.Use(func(c *fiber.Ctx) error {
		fmt.Printf("Request path: %s\n", c.Path())
		path := c.Path()
		// Skip auth for login-related endpoints and hello
		if path == "/hello" || path == "/login" || strings.HasPrefix(path, "/login/") {
			return c.Next()
		}

		token := c.Get("X-CSRF-Token")
		if token == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Missing X-CSRF-Token header",
			})
		}
		return c.Next()
	})

	app.Use(func(c *fiber.Ctx) error {
		path := c.Path()
		// Skip auth for login-related endpoints and hello
		if path == "/hello" || path == "/login" || strings.HasPrefix(path, "/login/") {
			return c.Next()
		}

		if globals.DevMode {
			return c.Next()
		}

		token := c.Get("Authorization")
		if token == "" || (!strings.HasPrefix(token, "Bearer ") && !strings.HasPrefix(token, "Token ")) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Missing Authorization header",
			})
		}

		if strings.HasPrefix(token, "Token ") {
			tokenStr := strings.TrimPrefix(token, "Token ")
			decodedData, err := utils.DecodeBase64(tokenStr)
			if err != nil {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error": "Invalid token: " + tokenStr,
				})
			}

			parts := strings.Split(decodedData, ".")
			if len(parts) < 4 {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error": "Malformed token: " + tokenStr,
				})
			}

			key, _, _, _ := parts[0], parts[1], parts[2], parts[3]

			valid, err := utils.ValidateAuth(fmt.Sprint(time.Now().UnixNano()/int64(time.Millisecond)), key)
			if err != nil || !*valid {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error": "Invalid token: " + tokenStr,
				})
			}
		} else {
			tokenStr := strings.TrimPrefix(token, "Bearer ")
			valid, err := utils.ValidateToken(tokenStr)
			if err != nil || !*valid {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error": "Invalid token: " + tokenStr,
				})
			}
		}

		return c.Next()
	})

	// Universal error handling middleware
	app.Use(func(c *fiber.Ctx) error {
		err := c.Next()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		return nil
	})

	cacheConfig := cache.Config{
		Next: func(c *fiber.Ctx) bool {
			return c.Method() != "GET"
		},
		Expiration: 2 * time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.Path() + "_" + c.Get("X-CSRF-Token")
		},
	}

	api := app.Group("/", func(c *fiber.Ctx) error {
		fmt.Printf("Request path: %s\n", c.Path())
		path := c.Path()
		// Skip auth for login-related endpoints and hello
		if path == "/hello" || path == "/login" || strings.HasPrefix(path, "/login/") {
			return c.Next()
		}
		token := c.Get("X-CSRF-Token")
		if token == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Missing X-CSRF-Token header",
			})
		}
		return c.Next()
	})

	// Routes -----------------------------------------

	app.Get("/hello", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "Hello, World!"})
	})

	// Step 1: Email lookup - validates email and returns identifier/digest or captcha
	app.Post("/login/lookup", func(c *fiber.Ctx) error {
		var body struct {
			Email string `json:"email"`
		}

		if err := c.BodyParser(&body); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid JSON body",
			})
		}

		if body.Email == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Missing email",
			})
		}

		lf := &handlers.LoginFetcher{}
		result, err := lf.Lookup(body.Email)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.JSON(result)
	})

	// Fetch captcha image by cdigest
	app.Get("/login/captcha/:cdigest", func(c *fiber.Ctx) error {
		cdigest := c.Params("cdigest")
		if cdigest == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Missing cdigest parameter",
			})
		}

		lf := &handlers.LoginFetcher{}
		image, err := lf.FetchCaptcha(cdigest)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.JSON(fiber.Map{
			"image":   image,
			"cdigest": cdigest,
		})
	})

	// Verify captcha and get new lookup data (identifier/digest)
	app.Post("/login/captcha", func(c *fiber.Ctx) error {
		var body struct {
			Username string `json:"username"`
			Cdigest  string `json:"cdigest"`
			Captcha  string `json:"captcha"`
		}

		if err := c.BodyParser(&body); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid JSON body",
			})
		}

		if body.Username == "" || body.Cdigest == "" || body.Captcha == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Missing username, cdigest, or captcha",
			})
		}

		lf := &handlers.LoginFetcher{}
		result, err := lf.CaptchaVerify(body.Username, body.Cdigest, body.Captcha)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.JSON(result)
	})

	// Step 2: Password verification - uses identifier/digest from lookup
	app.Post("/login/password", func(c *fiber.Ctx) error {
		var body struct {
			Identifier string `json:"identifier"`
			Digest     string `json:"digest"`
			Password   string `json:"password"`
		}

		if err := c.BodyParser(&body); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid JSON body",
			})
		}

		if body.Identifier == "" || body.Digest == "" || body.Password == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Missing identifier, digest, or password",
			})
		}

		lf := &handlers.LoginFetcher{}
		result, err := lf.VerifyPassword(body.Identifier, body.Digest, body.Password)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.JSON(result)
	})

	// Legacy /login endpoint for backwards compatibility
	app.Post("/login", func(c *fiber.Ctx) error {
		var creds struct {
			Username string  `json:"account"`
			Password string  `json:"password"`
			Cdigest  *string `json:"cdigest,omitempty"`
			Captcha  *string `json:"captcha,omitempty"`
		}

		if err := c.BodyParser(&creds); err != nil {
			log.Printf("Error parsing body: %v", err)
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid JSON body",
			})
		}

		if creds.Username == "" || creds.Password == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Missing account or password",
			})
		}

		lf := &handlers.LoginFetcher{}
		session, err := lf.Login(creds.Username, creds.Password, creds.Cdigest, creds.Captcha)
		if err != nil {
			return err
		}

		return c.JSON(session)
	})

	api.Delete("/logout", func(c *fiber.Ctx) error {
		lf := &handlers.LoginFetcher{}
		session, err := lf.Logout(c.Get("X-CSRF-Token"))
		if err != nil {
			return err
		}
		return c.JSON(session)
	})

	api.Get("/attendance", cache.New(cacheConfig), func(c *fiber.Ctx) error {
		attendance, err := handlers.GetAttendance(c.Get("X-CSRF-Token"))
		if err != nil {
			return err
		}
		return c.JSON(attendance)
	})

	api.Get("/marks", cache.New(cacheConfig), func(c *fiber.Ctx) error {
		marks, err := handlers.GetMarks(c.Get("X-CSRF-Token"))
		if err != nil {
			return err
		}
		return c.JSON(marks)
	})

	api.Get("/courses", cache.New(cacheConfig), func(c *fiber.Ctx) error {
		courses, err := handlers.GetCourses(c.Get("X-CSRF-Token"))
		if err != nil {
			return err
		}
		return c.JSON(courses)
	})

	api.Get("/user", cache.New(cacheConfig), func(c *fiber.Ctx) error {
		user, err := handlers.GetUser(c.Get("X-CSRF-Token"))
		if err != nil {
			return err
		}
		return c.JSON(user)
	})

	api.Get("/calendar", cache.New(cacheConfig), func(c *fiber.Ctx) error {
		db, err := databases.NewCalDBHelper()
		if err != nil {
			return err
		}

		dbcal, err := db.GetEvents()
		if err != nil {
			return err
		}

		if len(dbcal.Calendar) == 0 {
			cal, err := handlers.GetCalendar(c.Get("X-CSRF-Token"))
			if err != nil {
				return err
			}
			go func() {
				for _, event := range cal.Calendar {
					for _, month := range event.Days {
						err = db.SetEvent(databases.CalendarEvent{
							ID:        utils.GenerateID(),
							Date:      month.Date,
							Month:     event.Month,
							Day:       month.Day,
							Order:     month.DayOrder,
							Event:     month.Event,
							CreatedAt: time.Now().UnixNano() / int64(time.Millisecond),
						})

						if err != nil {
							log.Printf("Error setting calendar event: %v", err)
							return
						}
					}
				}
			}()
			return c.JSON(cal)
		}

		return c.JSON(dbcal)

	})

	api.Get("/timetable", cache.New(cacheConfig), func(c *fiber.Ctx) error {
		tt, err := handlers.GetTimetable(c.Get("X-CSRF-Token"))
		if err != nil {
			return err
		}
		return c.JSON(tt)
	})

	api.Get("/get", cache.New(cacheConfig), func(c *fiber.Ctx) error {
		token := c.Get("X-CSRF-Token")
		encodedToken := utils.Encode(token)

		db, err := databases.NewDatabaseHelper()
		if err != nil {
			return err
		}

		cachedData, err := db.FindByToken("goscrape", encodedToken)

		// Check if cached data exists and all required fields are present and non-empty
		if len(cachedData) != 0 &&
			cachedData["timetable"] != nil &&
			cachedData["attendance"] != nil &&
			cachedData["marks"] != nil {

			fmt.Print("I mean cached?")
			// Always fetch ophour from db and add to cachedData
			ophour, err := db.GetOphourByToken(encodedToken)
			if err == nil && ophour != "" {
				cachedData["ophour"] = ophour
			}

			go func() {
				data, err := fetchAllData(token)
				fmt.Print(data)
				if err != nil {
					return
				}
				if data != nil {
					data["token"] = encodedToken
					db.UpsertData("goscrape", data)
				}
			}()

			return c.JSON(cachedData)
		}

		data, err := fetchAllData(token)
		if err != nil {
			return utils.HandleError(c, err)
		}

		data["token"] = encodedToken

		js, _ := json.Marshal(data)

		go func() {
			err = db.UpsertData("goscrape", data)
		}()

		var responseData map[string]interface{}
		if err := json.Unmarshal(js, &responseData); err != nil {
			return err
		}
		return c.JSON(responseData)
	})

	// ----------------------------------------------------

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Starting server on port %s...", port)
	ln, err := net.Listen("tcp", "[::]:"+port)
	if err != nil {
		log.Fatalf("Failed to bind: %v", err)
	}
	log.Printf("Starting server on port %s...", port)
	if err := app.Listener(ln); err != nil {
		log.Printf("Server error: %+v", err)
	}
}

func fetchAllData(token string) (map[string]interface{}, error) {
	type result struct {
		key  string
		data interface{}
		err  error
	}

	resultChan := make(chan result, 5)

	go func() {
		data, err := handlers.GetUser(token)
		resultChan <- result{"user", data, err}
	}()
	go func() {
		data, err := handlers.GetAttendance(token)
		resultChan <- result{"attendance", data, err}
	}()
	go func() {
		data, err := handlers.GetMarks(token)
		resultChan <- result{"marks", data, err}
	}()
	go func() {
		data, err := handlers.GetCourses(token)
		resultChan <- result{"courses", data, err}
	}()
	go func() {
		data, err := handlers.GetTimetable(token)
		resultChan <- result{"timetable", data, err}
	}()

	data := make(map[string]interface{})

	for i := 0; i < 5; i++ {
		r := <-resultChan

		if r.err != nil {
			log.Printf(
				"fetchAllData error | key=%s | err=%v",
				r.key,
				r.err,
			)
			log.Printf(
				"partial response so far: %+v",
				data,
			)
			return nil, r.err
		}

		log.Printf(
			"fetchAllData success | key=%s | type=%T",
			r.key,
			r.data,
		)

		data[r.key] = r.data
	}

	if user, ok := data["user"].(*types.User); ok {
		data["regNumber"] = user.RegNumber
	}

	db, err := databases.NewDatabaseHelper()
	if err != nil {
		log.Printf("database init failed | err=%v", err)
	} else {
		encodedToken := utils.Encode(token)
		ophour, err := db.GetOphourByToken(encodedToken)
		if err != nil {
			log.Printf(
				"ophour fetch failed | token=%s | err=%v",
				encodedToken,
				err,
			)
		} else if ophour != "" {
			data["ophour"] = ophour
		}
	}

	log.Printf("fetchAllData final response: %+v", data)

	return data, nil
}
