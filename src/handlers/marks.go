package handlers

import (
	"goscraper/src/helpers"
	"goscraper/src/types"
)

func GetMarks(token string) (*types.MarksResponse, error) {
	scraper := helpers.NewAcademicsFetch(token)
	marks, err := scraper.GetMarks()

	return marks, err

}
