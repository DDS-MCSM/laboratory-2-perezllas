#******************************************************************************#
#                                                                              #
#                          Lab 2 - CPE Standard                                #
#                                                                              #
#              Arnau Sangra Rocamora - Data Driven Securty                     #
#                                                                              #
#******************************************************************************#

# install.packages("xml2")
library(xml2)
library(dplyr)
library(tidyr)
compressed_cpes_url <- "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip"
cpes_filename <- "cpes.zip"
download.file(compressed_cpes_url, cpes_filename)
unzip(zipfile = cpes_filename)
cpe.file <- "official-cpe-dictionary_v2.3.xml"

GetCPEItems <- function(cpe.raw) {
  #cpe <- read_xml(cpe.file)
  cpe.raw <- xml_find_all(cpe.raw, "//d1:cpe-item")
  cpe.name <- xml_find_all(cpe.raw, "//@name")
  cpe.title <- xml_find_all(cpe.raw, "//d1:title")
  cpe.subname <- xml_find_all(cpe.raw, "//cpe-23:cpe23-item/@name")
  cpe.reference <- xml_find_all(cpe.raw, "//d1:reference/@href")
  # transform the list to data frame
  cpe.name <- xml_text(cpe.name)
  cpe.name <- as.data.frame(cpe.name)
  cpe.title <- xml_text(cpe.title)
  cpe.title <- as.data.frame(cpe.title)
  cpe.subname <- xml_text(cpe.subname)
  cpe.subname <- as.data.frame(cpe.subname)
  cpe.reference <- xml_text(cpe.reference)
  cpe.reference <- as.data.frame(cpe.reference)
  df <- merge(data.frame(cpe.name, row.names=NULL), data.frame(cpe.title, row.names=NULL), by = 0, all = TRUE)[-1]
  df <- merge(data.frame(df, row.names=NULL), data.frame(cpe.subname, row.names=NULL), by = 0, all = TRUE)[-1]
  df <- merge(data.frame(df, row.names=NULL), data.frame(cpe.reference, row.names=NULL), by = 0, all = TRUE)[-1]
  
  # return data frame
  return(df)
}

CleanCPEs <- function(cpes){
  # data manipulation
  tidy.columns <- c("standard", "version", "part",
                  "vendor", "product","version",
                  "update", "edition", "language",
                  "edition_sw","target_sw", "target_host", "other")
  
  cpes <- separate(data = cpes, col = cpe.subname, into = tidy.columns, sep = "(?<=[^\\\\]):", remove = F)
  cpes$standard <- as.factor(cpes$standard)
  cpes$version <- as.factor(cpes$version)
  cpes$part <- as.factor(cpes$part)
  cpes$vendor <- as.factor(cpes$vendor)
  cpes$product <- as.factor(cpes$product)
  cpes$version <- as.factor(cpes$version)
  cpes$update <- as.factor(cpes$update)
  cpes$edition <- as.factor(cpes$edition)
  cpes$language <- as.factor(cpes$language)
  cpes$edition_sw <- as.factor(cpes$edition_sw)
  cpes$target_host <- as.factor(cpes$target_host)
  cpes$target_sw <- as.factor(cpes$target_sw)
  cpes
  return(cpes)
}

ParseCPEData <- function(cpe.file) {

  # load cpes as xml file
  cpes <- xml2::read_xml(x = cpe.file)
  cpes
  # get CPEs
  cpes <- GetCPEItems(cpes)
  # transform, clean, arrange parsed cpes as data frame
  df <- CleanCPEs(cpes)

  # return data frame
  return(df)
}

