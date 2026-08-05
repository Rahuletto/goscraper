package databases

import (
	"goscraper/src/globals"
	"goscraper/src/helpers"
	"goscraper/src/types"
	"os"
	"time"

	"github.com/joho/godotenv"
	"github.com/supabase-community/supabase-go"
)

type DBResponse struct {
	CreatedAt int64  `json:"created_at"`
	Date      string `json:"date"`
	Day       string `json:"day"`
	Event     string `json:"event"`
	ID        int64  `json:"id"`
	Month     string `json:"month"`
	Order     string `json:"order"`
}
type CalendarDatabaseHelper struct {
	client *supabase.Client
}

func NewCalDBHelper() (*CalendarDatabaseHelper, error) {
	if globals.DevMode {
		godotenv.Load()
	}
	supabaseUrl := os.Getenv("SUPABASE_URL")
	supabaseKey := os.Getenv("SUPABASE_KEY")

	client, err := supabase.NewClient(supabaseUrl, supabaseKey, nil)
	if err != nil {
		return nil, err
	}

	return &CalendarDatabaseHelper{
		client: client,
	}, nil
}

type CalendarEvent struct {
	ID        string `json:"id"`
	Date      string `json:"date"`
	Day       string `json:"day"`
	Month     string `json:"month"`
	Order     string `json:"order"`
	Event     string `json:"event"`
	CreatedAt int64  `json:"created_at"`
}

// SetEvent upserts on (month, date). /calendar only writes when gocal is empty
// and does so from a goroutine, so two requests arriving before either finishes
// both see an empty table and both insert the whole calendar, storing every day
// twice. Upserting makes the write idempotent; it needs the unique index on
// (month, date) documented in the README.
func (h *CalendarDatabaseHelper) SetEvent(event CalendarEvent) error {
	_, _, err := h.client.From("gocal").Insert(event, true, "month,date", "", "").Execute()
	return err
}

func (h *CalendarDatabaseHelper) GetEvents() (types.CalendarResponse, error) {
	var events []DBResponse
	_, err := h.client.From("gocal").Select("*", "", false).ExecuteTo(&events)
	if err != nil {
		return types.CalendarResponse{}, err
	}

	if len(events) == 0 {
		return types.CalendarResponse{}, nil
	}

	var response []types.CalendarMonth = make([]types.CalendarMonth, 0)
	monthMap := make(map[string]*types.CalendarMonth)

	for _, event := range events {
		if month, exists := monthMap[event.Month]; exists {
			month.Days = append(month.Days, types.Day{
				Date:     event.Date,
				Day:      event.Day,
				Event:    event.Event,
				DayOrder: event.Order,
			})
		} else {
			newMonth := &types.CalendarMonth{
				Month: event.Month,
				Days: []types.Day{{
					Date:     event.Date,
					Day:      event.Day,
					Event:    event.Event,
					DayOrder: event.Order,
				}},
			}
			monthMap[event.Month] = newMonth
		}
	}

	for _, month := range monthMap {
		response = append(response, *month)
	}

	sortedData := helpers.SortCalendarData(response)

	today, tomorrow, monthIndex := helpers.SelectToday(sortedData, time.Now())

	resp := types.CalendarResponse{
		Today:    today,
		Tomorrow: tomorrow,
		Index:    monthIndex,
		Calendar: sortedData,
		Status:   200,
		Message:  "From DB",
	}

	return resp, nil
}
