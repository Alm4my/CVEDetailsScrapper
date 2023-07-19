package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/cheggaaa/pb/v3"
	"github.com/tealeg/xlsx"
)

// Vulnerability struct to format the vulnerabilities
type Vulnerability struct {
	CVE                string // Common Vulnerabilities and Exposures
	CWE                string // Common Weakness Enumeration
	Description        string
	Exploits           string // number of exploits
	VulnerabilityTypes string
	PublishDate        string
	UpdateDate         string
	Score              string
	GainedAccessLevel  string
	AccessComplexity   string
	Authentication     string
	Confidentiality    string
	Integrity          string
	Availability       string
}

func main() {
	// Welcome Message
	fmt.Println("============================================")
	fmt.Println("Welcome to the CVEDetails.com Scrapper!")
	fmt.Println("You can scrap data from https://cvedetails.com \naccording to the year, and the different pages.")
	fmt.Println("============================================\n")

	// Prompt user for year, start and end page inputs
	var startPage, endPage, year int
	fmt.Print("Enter the year you're trying to scrap for: ")
	_, err := fmt.Scanln(&year)
	if err != nil {
		fmt.Println("Please enter a number for the year.")
		return
	}
	fmt.Print("Enter the start page number: ")
	_, err = fmt.Scanln(&startPage)
	if err != nil {
		fmt.Println("Please enter a number for the start page.")
		return
	}
	fmt.Print("Enter the end page number: ")
	_, err = fmt.Scanln(&endPage)
	if err != nil {
		fmt.Println("Please enter a number for the end page.")
		return
	}

	// Create a slice to store the vulnerabilities
	var vulnerabilities []Vulnerability

	// Initialize the progress bar
	totalPages := endPage - startPage + 1
	bar := pb.StartNew(totalPages)

	// Loop through the pages
	for page := startPage; page <= endPage; page++ {
		// Construct the URL with page query
		url := fmt.Sprintf("https://www.cvedetails.com/vulnerability-list.php?vendor_id=0&product_id=0&version_id=0&page=%d&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=0&cvssscoremax=0&year=%d&month=0&cweid=0&order=1&trc=20171&sha=5865744384614acda35d0681e9e72ad105514ab2", page, year)

		// Fetch the HTML content from the web
		resp, err := http.Get(url)
		if err != nil {
			log.Fatal(err)
		}

		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
			}
		}(resp.Body)

		// Create a new document and load the HTML content
		doc, err := goquery.NewDocumentFromReader(resp.Body)
		if err != nil {
			log.Fatal(err)
		}

		// Find the rows with class 'srrowns'
		doc.Find("tr.srrowns").Each(func(i int, rowSelection *goquery.Selection) {
			// Create a new vulnerability object
			vuln := Vulnerability{}

			// Get the cells in the row
			rowSelection.Find("td").Each(func(j int, cellSelection *goquery.Selection) {
				cellText := strings.TrimSpace(cellSelection.Text())

				// Extract the relevant data based on the cell's index
				switch j {
				case 1:
					vuln.CVE = cellSelection.Find("a").Text()
				case 2:
					vuln.CWE = cellSelection.Find("a").Text()
				case 3:
					vuln.Exploits = cellText
				case 4:
					vuln.VulnerabilityTypes = cellText
				case 5:
					vuln.PublishDate = cellText
				case 6:
					vuln.UpdateDate = cellText
				case 7:
					vuln.Score = cellText
				case 8:
					vuln.GainedAccessLevel = cellText
				case 9:
					vuln.AccessComplexity = cellText
				case 10:
					vuln.Authentication = cellText
				case 11:
					vuln.Confidentiality = cellText
				case 12:
					vuln.Integrity = cellText
				case 13:
					vuln.Availability = cellText
				}
			})

			// Find the next row and get the description
			description := rowSelection.Next().Find("td.cvesummarylong").Text()
			vuln.Description = strings.TrimSpace(description)

			// Append the vulnerability to the slice
			vulnerabilities = append(vulnerabilities, vuln)
		})

		// Increment the progress bar
		bar.Increment()
	}

	// Finish the progress bar
	bar.Finish()

	// Prompt user for export format
	var exportFormat string
	fmt.Print("Enter export format (csv or xlsx) default to csv: ")
	_, err = fmt.Scanln(&exportFormat)

	var fileName string
	fmt.Print("Enter the file name (default: vulnerabilities.csv[.xlsx]): ")
	_, err = fmt.Scanln(&fileName)

	// Validates filename
	if !isValidFilename(fileName) {
		fmt.Printf("Filename '%s' is invalid.\n"+
			"The filename should be alhpanueric characters only. e.g. MyFileName.csv", fileName)
		return
	}

	// Export the data based on the chosen format
	switch strings.ToLower(exportFormat) {
	case "xlsx", "excel", "x":
		if len(fileName) > 0 {
			exportCSV(vulnerabilities, fileName)
		} else {
			exportXLSX(vulnerabilities, "vulnerabilities.xlsx")
		}
	default:
		if len(fileName) > 0 {
			exportCSV(vulnerabilities, fileName)
		} else {
			exportCSV(vulnerabilities, "vulnerabilities.csv")
		}
	}
}

func exportCSV(vulnerabilities []Vulnerability, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)

	// Write the header
	_, err = file.WriteString("CVE,CWE,# of Exploits,Vulnerability Types,Publish Date,Update Date,Score,Gained Access Level,Access Complexity,Authentication,Confidentiality Impact,Integrity Impact,Availability Impact,Description\n")
	if err != nil {
		return
	}

	// Write each vulnerability to the file
	for _, vuln := range vulnerabilities {
		_, err := file.WriteString(fmt.Sprintf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
			vuln.CVE, vuln.CWE, vuln.Exploits, vuln.VulnerabilityTypes, vuln.PublishDate, vuln.UpdateDate,
			vuln.Score, vuln.GainedAccessLevel, vuln.AccessComplexity, vuln.Authentication, vuln.Confidentiality,
			vuln.Integrity, vuln.Availability, vuln.Description))
		if err != nil {
			return
		}
	}

	fmt.Printf("Data exported to %s\n", filename)
}

func exportXLSX(vulnerabilities []Vulnerability, filename string) {
	file := xlsx.NewFile()
	sheet, err := file.AddSheet("Vulnerabilities")
	if err != nil {
		log.Fatal(err)
	}

	// Write the header
	row := sheet.AddRow()
	row.AddCell().Value = "CVE"
	row.AddCell().Value = "CWE"
	row.AddCell().Value = "# of Exploits"
	row.AddCell().Value = "Vulnerability Types"
	row.AddCell().Value = "Publish Date"
	row.AddCell().Value = "Update Date"
	row.AddCell().Value = "Score"
	row.AddCell().Value = "Gained Access Level"
	row.AddCell().Value = "Access Complexity"
	row.AddCell().Value = "Authentication"
	row.AddCell().Value = "Confidentiality Impact"
	row.AddCell().Value = "Integrity Impact"
	row.AddCell().Value = "Availability Impact"
	row.AddCell().Value = "Description"

	// Write each vulnerability to the sheet
	for _, vuln := range vulnerabilities {
		row = sheet.AddRow()
		row.AddCell().Value = vuln.CVE
		row.AddCell().Value = vuln.CWE
		row.AddCell().Value = vuln.Exploits
		row.AddCell().Value = vuln.VulnerabilityTypes
		row.AddCell().Value = vuln.PublishDate
		row.AddCell().Value = vuln.UpdateDate
		row.AddCell().Value = vuln.Score
		row.AddCell().Value = vuln.GainedAccessLevel
		row.AddCell().Value = vuln.AccessComplexity
		row.AddCell().Value = vuln.Authentication
		row.AddCell().Value = vuln.Confidentiality
		row.AddCell().Value = vuln.Integrity
		row.AddCell().Value = vuln.Availability
		row.AddCell().Value = vuln.Description

	}

	err = file.Save(filename)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Data exported to %s\n", filename)
}

func isValidFilename(fileName string) bool {
	if fileName == "" {
		return true
	}
	// Regex for whitelisted characters: alphanumeric, _,- and .
	allowedPattern := `^[a-zA-Z0-9_]+([-_][a-zA-Z0-9]+)*(\.[a-zA-Z0-9]+)?$`

	// Compile the regular expression.
	regex, err := regexp.Compile(allowedPattern)
	if err != nil {
		// Handle any errors in regex compilation
		fmt.Println("Error compiling regex:", err)
		return false
	}

	// Check if the filename matches the allowed pattern.
	return regex.MatchString(fileName)
}
