# CVEDetailsScrapper
## Purpose
The purpose of this script is to retrieve data from https://cvedetails.com.
It will retrieve the data according to the year, and pages.
It can be then exported to either csv or xlsx (Excel Format).

## Usage
To use the script, you need to have golang installed,
compile it and then execute it.

#### Golang Installation
see https://go.dev/doc/install

#### Windows
```PowerShell
# clone the repository
git clone https://github.com/alm4my/CVEDetailsScrapper.git
cd CVEDetailsScrapper

# retrieve the packages
go get

# build the executable
go build -o CVEDetailScrapper.exe .\main.go

# Run the script either by double clicking the executable or running the command below
.\CVEDetailScrapper.exe

```

#### Linux
```bash
# clone the repository
git clone https://github.com/alm4my/CVEDetailsScrapper.git

# change into the directory
cd CVEDetailsScrapper

# retrieve the packages
go get

```
```bash
# build the executable
go build -o CVEDetailScrapper ./main.go
```
```bash
# Run the script either by double clicking the executable or running the command below
./CVEDetailScrapper
```

## Todo & Possible Improvements
- [x] Create release versions for different operating systems
- [ ] Add more advanced filtering capabilities
- [ ] Enable arguments to be passed to the script