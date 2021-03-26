package main

import (
	"encoding/json"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"io/ioutil"
	"net/http"
)

type Config struct {
	ClientId     string
	ClientSecret string
	RedirectUrl  string
}

type Token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
}

var config = Config{
	ClientId:     clientId,
	ClientSecret: clientSecret,
	RedirectUrl:  "http://localhost:1323/redirect",
}


func main()  {
	e:=echo.New()
	e.Use(middleware.Recover())
	e.Use(middleware.Logger())
	e.GET("/",Index)
	e.GET("/oauth",Oauth)
	e.GET("/redirect",Redirect)
	e.GET("/hello",Hello)
	e.Logger.Fatal(e.Start(":1323"))
}

func Index(c echo.Context) error {
	html:=`<html lang="en">
	<head>
	<meta charset="UTF-8">
	<title>Title</title>
	</head>
	<body>
	<a href="http://localhost:1323/oauth">Github 第三方授权登录</a>
	</body>
	</html>`
	return c.HTML(http.StatusOK,html)
}

func Hello(c echo.Context) error {
	userinfo:=c.Get("userinfo").(map[string]interface{})
	name:=userinfo["name"].(string)
	page:=userinfo["html_url"].(string)
	html:=fmt.Sprintf(`<html lang="en">
	<head>
	<meta charset="UTF-8">
	<title>Title</title>
	</head>
	<body>
	Hello, <a href="%v">%v</a>
	</body>
	</html>`,page,name)
	//return c.JSON(http.StatusOK,userinfo)
	return  c.HTML(http.StatusOK,html)
}

func Redirect(c echo.Context) error {
	code:=c.QueryParam("code")
	tokenUrl:=GetTokenUrl(code)
	token,err:=GetToken(tokenUrl)
	if err!=nil {
		return c.JSON(http.StatusBadRequest,err)
	}
	userinfo,err:=GetUserInfo(token)
	if err!=nil{
		return c.JSON(http.StatusBadRequest,err)
	}
	c.Set("userinfo",userinfo)
	//return c.JSON(http.StatusOK,userinfo)
	return c.Redirect(http.StatusMovedPermanently,"http://localhost:1323/hello")
}

func Oauth(c echo.Context) error {
	return c.Redirect(http.StatusMovedPermanently,fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%v&redirect_uri=%v",config.ClientId,config.RedirectUrl))
}

func GetTokenUrl(code string) string {
	return fmt.Sprintf(
		"https://github.com/login/oauth/access_token?client_id=%s&client_secret=%s&code=%s",
		config.ClientId, config.ClientSecret, code,
	)
}

func GetToken(url string) (*Token, error) {
	var req *http.Request
	var err error
	if req, err = http.NewRequest(http.MethodGet, url, nil); err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/json")

	var httpClient = http.Client{}
	var res *http.Response
	if res, err = httpClient.Do(req); err != nil {
		return nil, err
	}

	var token Token
	if err = json.NewDecoder(res.Body).Decode(&token); err != nil {
		return nil, err
	}
	return &token, nil
}


func GetUserInfo(token *Token) (map[string]interface{}, error) {
	var userInfoUrl = "https://api.github.com/user"
	var req *http.Request
	var err error
	if req, err = http.NewRequest(http.MethodGet, userInfoUrl, nil); err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("token %s", token.AccessToken))

	var client = http.Client{}
	var rsp *http.Response
	if rsp, err = client.Do(req); err != nil {
		return nil, err
	}

	content, _ := ioutil.ReadAll(rsp.Body)
	var userInfo = make(map[string]interface{})
	if err = json.Unmarshal(content, &userInfo); err != nil {
		return nil, err
	}
	return userInfo, nil
}