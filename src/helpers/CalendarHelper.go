package helpers

import (
	"fmt"
	"goscraper/src/types"
	"goscraper/src/utils"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/valyala/fasthttp"
)

func init() {
	// Load .env file from the project root
	// if err := godotenv.Load(); err != nil {
	//     fmt.Printf("Warning: .env file not found: %v\n", err)
	// }
}

type CalendarFetcher struct {
	cookie string
	date   time.Time
}

func NewCalendarFetcher(date time.Time, cookie string) *CalendarFetcher {
	return &CalendarFetcher{
		cookie: cookie,
		date:   date,
	}
}

func (c *CalendarFetcher) GetCalendar() (*types.CalendarResponse, error) {
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("https://academia.srmist.edu.in/srm_university/academia-academic-services/page/" + PlannerPage(c.date))
	req.Header.SetMethod("GET")
	req.Header.Set("accept", "*/*")
	req.Header.Set("accept-language", "en-US,en;q=0.9")
	req.Header.Set("content-type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("cookie", fmt.Sprintf("ZCNEWUIPUBLICPORTAL=true; cli_rgn=IN; %s", utils.ExtractCookies(c.cookie)))
	req.Header.Set("Referer", "https://academia.srmist.edu.in/")
	req.Header.Set("Cache-Control", "public, max-age=3600, stale-while-revalidate=7200")

	if err := fasthttp.Do(req, resp); err != nil {
		log.Printf("CalendarHelper.GetCalendar: failed to fetch calendar - %v", err)
		return &types.CalendarResponse{
			Error:    true,
			Message:  err.Error(),
			Status:   500,
			Calendar: []types.CalendarMonth{},
		}, nil
	}

	statusCode := resp.StatusCode()
	if statusCode != fasthttp.StatusOK {
		log.Printf("CalendarHelper.GetCalendar: server returned status %d", statusCode)
		return &types.CalendarResponse{
			Error:    true,
			Message:  fmt.Sprintf("HTTP error: %d", statusCode),
			Status:   statusCode,
			Calendar: []types.CalendarMonth{},
		}, nil
	}

	calendar, err := c.parseCalendar(string(resp.Body()))
	if err != nil {
		log.Printf("CalendarHelper.GetCalendar: failed to parse calendar - %v", err)
		return &types.CalendarResponse{
			Error:    true,
			Message:  err.Error(),
			Status:   500,
			Calendar: []types.CalendarMonth{},
		}, nil
	}

	calendar.Status = statusCode
	return calendar, nil
}

func (c *CalendarFetcher) parseCalendar(html string) (*types.CalendarResponse, error) {
	var htmlText string
	if strings.Contains(html, "<table bgcolor=") {
		htmlText = html
	} else {
		parts := strings.Split(html, "zmlvalue=\"")
		if len(parts) < 2 {
			log.Printf("CalendarHelper.parseCalendar: invalid HTML format")
			return &types.CalendarResponse{
				Error:    true,
				Message:  "invalid HTML format",
				Status:   500,
				Calendar: []types.CalendarMonth{},
			}, nil
		}
		decodedHTML := utils.ConvertHexToHTML(strings.Split(parts[1], "\" > </div> </div>")[0])
		htmlText = utils.DecodeHTMLEntities(decodedHTML)
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlText))
	if err != nil {
		log.Printf("CalendarHelper.parseCalendar: failed to parse HTML - %v", err)
		return &types.CalendarResponse{
			Error:    true,
			Message:  err.Error(),
			Status:   500,
			Calendar: []types.CalendarMonth{},
		}, nil
	}

	var monthHeaders []string
	doc.Find("th").Each(func(_ int, s *goquery.Selection) {
		month := strings.TrimSpace(s.Text())
		if strings.Contains(month, "'2") {
			monthHeaders = append(monthHeaders, month)
		}
	})

	data := make([]types.CalendarMonth, len(monthHeaders))
	for i := range monthHeaders {
		data[i].Month = monthHeaders[i]
		data[i].Days = make([]types.Day, 0)
	}

	doc.Find("table tr").Each(func(_ int, row *goquery.Selection) {
		tds := row.Find("td")
		for i := range monthHeaders {
			pad := 0
			if i > 0 {
				pad = i * 5
			}

			date := strings.TrimSpace(tds.Eq(pad).Text())
			day := strings.TrimSpace(tds.Eq(pad + 1).Text())
			event := strings.TrimSpace(tds.Eq(pad + 2).Text())
			dayOrder := strings.TrimSpace(tds.Eq(pad + 3).Text())

			if date != "" && dayOrder != "" {
				data[i].Days = append(data[i].Days, types.Day{
					Date:     date,
					Day:      day,
					Event:    event,
					DayOrder: dayOrder,
				})
			}
		}
	})

	// Sort the calendar data
	sortedData := SortCalendarData(data)

	today, tomorrow, monthIndex := SelectToday(sortedData, c.date)

	return &types.CalendarResponse{
		Today:    today,
		Tomorrow: tomorrow,
		Index:    monthIndex,
		Calendar: sortedData,
	}, nil
}

// PlannerPage returns the academic planner page for the semester containing
// date. SRM's academic year runs July to June: July-December is the ODD
// semester of year/year+1, January-June the EVEN semester of year-1/year.
func PlannerPage(date time.Time) string {
	year, semester := date.Year(), "ODD"
	if date.Month() < time.July {
		year, semester = date.Year()-1, "EVEN"
	}
	return fmt.Sprintf("Academic_Planner_%d_%02d_%s", year, (year+1)%100, semester)
}

// SelectToday locates date within sorted calendar data and returns the matching
// day, the day after it, and the index of the month holding it.
//
// Days are matched on their date value rather than their position, because a
// month may start partway through (a semester beginning mid-month) which leaves
// Days[n] holding some day other than n+1. When date's month is absent from the
// calendar entirely, both days are nil: the caller is outside the range this
// planner covers, and reporting some unrelated day as "today" is worse than
// reporting nothing.
func SelectToday(sorted []types.CalendarMonth, date time.Time) (today, tomorrow *types.Day, monthIndex int) {
	monthNames := []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
	currentMonthName := monthNames[date.Month()-1]

	monthIndex = -1
	for i, entry := range sorted {
		if strings.Contains(entry.Month, currentMonthName) {
			monthIndex = i
			break
		}
	}
	if monthIndex == -1 {
		return nil, nil, 0
	}

	days := sorted[monthIndex].Days
	dayIndex := -1
	for i := range days {
		if d, err := strconv.Atoi(days[i].Date); err == nil && d == date.Day() {
			dayIndex = i
			break
		}
	}
	if dayIndex == -1 {
		return nil, nil, monthIndex
	}

	today = &days[dayIndex]
	if dayIndex+1 < len(days) {
		tomorrow = &days[dayIndex+1]
	} else if monthIndex+1 < len(sorted) && len(sorted[monthIndex+1].Days) > 0 {
		tomorrow = &sorted[monthIndex+1].Days[0]
	}
	return today, tomorrow, monthIndex
}

func SortCalendarData(data []types.CalendarMonth) []types.CalendarMonth {
	monthNames := []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}

	monthIndices := make(map[string]int)
	for i, month := range monthNames {
		monthIndices[month] = i
	}

	for i := 0; i < len(data)-1; i++ {
		for j := 0; j < len(data)-i-1; j++ {
			month1 := strings.Split(data[j].Month, "'")[0][:3]
			month2 := strings.Split(data[j+1].Month, "'")[0][:3]

			if monthIndices[month1] > monthIndices[month2] {
				data[j], data[j+1] = data[j+1], data[j]
			}
		}
	}

	for i := range data {
		for j := 0; j < len(data[i].Days)-1; j++ {
			for k := 0; k < len(data[i].Days)-j-1; k++ {
				date1, _ := strconv.Atoi(data[i].Days[k].Date)
				date2, _ := strconv.Atoi(data[i].Days[k+1].Date)
				if date1 > date2 {
					data[i].Days[k], data[i].Days[k+1] = data[i].Days[k+1], data[i].Days[k]
				}
			}
		}
	}

	return data
}
