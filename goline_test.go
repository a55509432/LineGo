package goline

import (
	"testing"
)

func TestLimit(t *testing.T) {
	me := NewLogin()
	me.Login("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJiMzBjZjM2OS05NTRmLTQzNGUtYTU4YS0zZmY3YjRjNDkwZTYiLCJhdWQiOiJMSU5FIiwiaWF0IjoxNzM0OTQ2MTk1LCJleHAiOjE3MzU1NTA5OTUsInNjcCI6IkxJTkVfQ09SRSIsInJ0aWQiOiI5MDk1YmQ5YS1mMjI2LTRlNTItYWVlNi04OTVkMzAzZDE4YjAiLCJyZXhwIjoxODkyNjI2MTk1LCJ2ZXIiOiIzLjEiLCJhaWQiOiJ1NGM0NWQ0NmU3MTA0OGFkNDhhMzg2YjZkMjBhYjE5MWMiLCJsc2lkIjoiYzQ3MzIyODQtODUwYS00ZTc5LTkzYjEtZDA4YzAzNjFiZDJkIiwiZGlkIjoiNDQxZmYyNjc4ZTc3YWFkY2FhM2QxNThiYWIzNDhhYTIiLCJjdHlwZSI6IkFORFJPSUQiLCJjbW9kZSI6IlBSSU1BUlkiLCJjaWQiOiIwMDAwMDAwMDAwIn0.vYlz3_W_QgaHgeaVmxlu_C2ZUF2U14akemzbY1qyr_4")
	mids, err := me.GetAllContactIds()
	t.Log(len(mids), mids, err)
	// t.Log(me.DeleteOtherFromChat("c6fac0ad4a214beaf6da808d6ba7e3025", ""))
}

func TestNewDailer(t *testing.T) {
	me := NewLogin()
	me.setDefaultHttpClient()
	t.Log(me.fast_connection.Get([]byte{}, "https://google.com"))
}

func TestCreateTempEmail(t *testing.T) {
	// t.Log(createTempEmail())
	// t.Log(getTempmailMessage("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpYXQiOjE2MjMwNDk4NzAsInJvbGVzIjpbIlJPTEVfVVNFUiJdLCJ1c2VybmFtZSI6Ijg4MDhiNmQ1NjkwODFiZWQxMzhmOTlhMGIzMzg5MDRlQGxvZ2ljc3RyZWFrLmNvbSIsImlkIjoiNjBiZGM2OGQ0MTkyN2Y1YmI0MjBkZDkzIiwibWVyY3VyZSI6eyJzdWJzY3JpYmUiOlsiL2FjY291bnRzLzYwYmRjNjhkNDE5MjdmNWJiNDIwZGQ5MyJdfX0.kXHKiFxlV1QjpgZ9w8cszA7Xw4l2JSzl7Yte0ss6GK0rE4fmhg4iwqPveCrQCWlAXR2qxccV3MSGen-UqHTmhA"))
}
