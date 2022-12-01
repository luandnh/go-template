package util

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/araddon/dateparse"
	"github.com/google/uuid"
	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

func ParseString(value interface{}) string {
	str, ok := value.(string)
	if !ok {
		return str
	}
	str = strings.Replace(str, "\n", "", -1)
	str = strings.Trim(str, "\r\n")
	str = strings.TrimSpace(str)
	return str
}

func ParseStringToInt(str string) int {
	i, err := strconv.Atoi(str)
	if err != nil {
		return 0
	}
	return i
}

func ParseFloat64(value interface{}) float64 {
	typeData := reflect.ValueOf(value)
	str := ""
	if typeData.Kind() == reflect.String {
		str = ParseString(value)
	} else {
		str = fmt.Sprintf("%v", value)
	}
	i, err := strconv.ParseFloat(str, 64)
	if err != nil {
		i = 0
	}
	return i
}

func ParseOffset(offset string) int {
	offset = ParseString(offset)
	i, err := strconv.Atoi(offset)
	if err != nil {
		i = 0
	}
	return i
}

func ParseLimit(limit string) int {
	limit = ParseString(limit)
	i, err := strconv.Atoi(limit)
	if err != nil {
		i = 10
	}
	return i
}

var (
	timezone = ""
)

func ParseTime(str string) time.Time {
	loc, err := time.LoadLocation("Asia/Ho_Chi_Minh")
	time.Local = loc
	t, err := dateparse.ParseLocal(str)
	if err != nil {
		t = time.Now()
	}
	return t
}

func ParseMapToString(value interface{}) (string, error) {
	bytes, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func removeAccents(s string) string {
	t := transform.Chain(norm.NFD, runes.Remove(runes.In(unicode.Mn)), norm.NFC)
	output, _, e := transform.String(t, s)
	if e != nil {
		return s
	}
	return output
}

func UrlEncode(s string) string {
	res := url.QueryEscape(s)
	return res
}

func UrlDecode(s string) string {
	res, err := url.QueryUnescape(s)
	if err != nil {
		return s
	}
	return res
}

func IsValidUUID(u string) bool {
	_, err := uuid.Parse(u)
	return err == nil
}

func GetPageSize(pageSize string) int64 {
	pageSizeInt, err := strconv.ParseInt(pageSize, 10, 64)
	if err != nil {
		pageSizeInt = 50
	}
	return pageSizeInt
}

func CurrentTime() time.Time {
	return time.Now()
}

func CurrentTimeMicro() int64 {
	microTime := int64(time.Now().UnixNano() / 1000)
	return microTime
}

func TimeToString(valueTime time.Time) string {
	return TimeToStringLayout(valueTime, "2006-01-02 15:04:05")
}

func TimeToStringLayout(valueTime time.Time, layout string) string {
	return valueTime.Format(layout)
}

func ParseFromStringToTime(timeStr string) time.Time {
	return ParseFromStringToTimeLayout(timeStr, "2006-01-02 15:04:05")
}

func ParseFromStringToTimeLayout(timeStr string, layout string) time.Time {
	date, _ := time.Parse(layout, timeStr)
	return date
}

func CheckStartEndDate(startDate, endDate string) (time.Time, time.Time, error) {
	startTime := time.Now()
	endTime := time.Now()
	if startDate != "" {
		startTime = ParseFromStringToTime(startDate)
		if startTime.IsZero() {
			return time.Time{}, time.Time{}, errors.New("start_time is invalid")
		}
	} else {
		startDate = TimeToStringLayout(startTime, "2006-01-02") + " 00:00:00"
		startTime = ParseFromStringToTime(startDate)
	}
	if endDate != "" {
		endTime = ParseFromStringToTime(endDate)
		if endTime.IsZero() {
			return time.Time{}, time.Time{}, errors.New("end_time is invalid")
		}
	} else {
		endDate = TimeToStringLayout(startTime, "2006-01-02") + " 23:59:59"
		endTime = ParseFromStringToTime(endDate)
	}
	if startTime.After(endTime) {
		return time.Time{}, time.Time{}, errors.New("start_date must be after end_date")
	}
	return startTime, endTime, nil
}

func ParseQueryArray(slice []string) []string {
	result := make([]string, 0)
	for _, v := range slice {
		if len(v) > 0 {
			result = append(result, v)
		}
	}
	return result
}

func RemoveDuplicate(array []string) []string {
	m := make(map[string]string)
	for _, x := range array {
		m[x] = x
	}
	result := make([]string, 0)
	for x := range m {
		result = append(result, x)
	}
	return result
}

func InArray(item interface{}, array interface{}) bool {
	arr := reflect.ValueOf(array)
	if arr.Kind() != reflect.Slice {
		return false
	}
	for i := 0; i < arr.Len(); i++ {
		if arr.Index(i).Interface() == item {
			return true
		}
	}
	return false
}

func GetLocalTimeOfTime(val time.Time) time.Time {
	currentYear, currentMonth, currentDay := val.Date()
	loc, _ := time.LoadLocation("UTC")
	return time.Date(currentYear, currentMonth, currentDay, 0, 0, 0, 0, loc)
}

func ParseStartEndTime(startTimeStr, endTimeStr string, allowZero bool) (time.Time, time.Time, error) {
	today := time.Now()
	currentYear, currentMonth, currentDay := today.Date()
	loc, _ := time.LoadLocation("UTC")
	startTime := time.Date(currentYear, currentMonth, currentDay, 0, 0, 0, 0, loc)
	endTime := time.Date(currentYear, currentMonth, currentDay, 23, 59, 59, 0, loc)
	if allowZero && len(startTimeStr) < 1 {
		startTime = time.Time{}
	} else if len(startTimeStr) > 1 {
		startTime = ParseFromStringToTime(startTimeStr)
		if startTime.IsZero() {
			return time.Time{}, time.Time{}, errors.New("start_time is invalid")
		}
	}
	if allowZero && len(endTimeStr) < 1 {
		endTime = time.Time{}
	} else if len(endTimeStr) > 1 {
		endTime = ParseFromStringToTime(endTimeStr)
		if endTime.IsZero() {
			return time.Time{}, time.Time{}, errors.New("end_time is invalid")
		}
	}
	if startTime.After(endTime) {
		return time.Time{}, time.Time{}, errors.New("start_date must be after end_date")
	}
	return startTime, endTime, nil
}

func GetStartEndCurrent() (time.Time, time.Time) {
	today := time.Now()
	currentYear, currentMonth, currentDay := today.Date()
	loc, _ := time.LoadLocation("UTC")
	startTime := time.Date(currentYear, currentMonth, currentDay, 0, 0, 0, 0, loc)
	endTime := time.Date(currentYear, currentMonth, currentDay, 23, 59, 59, 0, loc)
	return startTime, endTime
}

func ParsesStringToStruct(value string, dest any) error {
	if err := json.Unmarshal([]byte(value), dest); err != nil {
		return err
	}
	return nil
}

func StringToBase64(str string) string {
	data := []byte(str)
	val := base64.StdEncoding.EncodeToString(data)
	return val
}

func ParseStructToMap(value any, dest any) error {
	bytes, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(bytes, dest); err != nil {
		return err
	}
	return nil
}

func ToLower(value string) string {
	return strings.ToLower(value)
}
