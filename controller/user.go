package controller

import (
	"encoding/json"
	"file-store/lib"
	"file-store/model"
	"file-store/util"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
)

type PrivateInfo struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    string `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	OpenId       string `json:"openid"`
}

// 登录成功获取的QQ用户信息
type QUserInfo struct {
	Nickname    string
	FigureUrlQQ string `json:"figureurl_qq"`
}

type UserInfo struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// 登录页
func Login(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", nil)
}

func CommonLogin(c *gin.Context) {
	username := c.PostForm("username")

	if ok := model.QueryUserExistsByName(username); !ok {
		c.JSON(http.StatusOK, gin.H{
			"code": 400,
			"msg":  "用户名或密码错误",
		})
		return
	}

	user := model.QueryUserByName(username)
	salt := user.Salt
	passwd := user.Password

	if passwd != util.EncodeMd5(c.PostForm("password")+salt) {
		c.JSON(http.StatusOK, gin.H{
			"code": 400,
			"msg":  "用户名或密码错误",
		})
		return
	}

	quser := &QUserInfo{}

	quser.Nickname = user.UserName
	quser.FigureUrlQQ = user.ImagePath

	jsonUser, _ := json.Marshal(quser)

	LoginSucceed(string(jsonUser), user.OpenId, c)
}

func CommonRegister(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	if ok := model.QueryUserExistsByName(username); ok {
		c.JSON(http.StatusOK, gin.H{
			"code": 400,
			"msg":  "用户名已存在",
		})
		return
	}

	user := &QUserInfo{}

	user.Nickname = username
	user.FigureUrlQQ = "https://avatar.iran.liara.run/public/boy?username=" + username

	openId := randomString(32)
	salt := randomString(16)
	passwd := util.EncodeMd5(password + salt)

	model.CreateUserCommon(openId, user.Nickname, passwd, salt, user.FigureUrlQQ)

	c.Redirect(http.StatusMovedPermanently, "/")
}

// 处理登录
func HandlerLogin(c *gin.Context) {
	conf := lib.LoadServerConfig()
	state := "xxxxxxx"
	url := "https://graph.qq.com/oauth2.0/authorize?response_type=code&client_id=" + conf.AppId + "&redirect_uri=" + conf.RedirectURI + "&state=" + state

	c.Redirect(http.StatusMovedPermanently, url)
}

// 获取access_token
func GetQQToken(c *gin.Context) {
	conf := lib.LoadServerConfig()
	code := c.Query("code")

	loginUrl := "https://graph.qq.com/oauth2.0/token?grant_type=authorization_code&client_id=" + conf.AppId + "&client_secret=" + conf.AppKey + "&redirect_uri=" + conf.RedirectURI + "&code=" + code

	response, err := http.Get(loginUrl)
	if err != nil {
		fmt.Println("请求错误", err.Error())
		return
	}
	defer response.Body.Close()

	bs, _ := ioutil.ReadAll(response.Body)
	body := string(bs)
	resultMap := util.ConvertToMap(body)

	info := &PrivateInfo{}
	info.AccessToken = resultMap["access_token"]
	info.RefreshToken = resultMap["refresh_token"]
	info.ExpiresIn = resultMap["expires_in"]

	GetOpenId(info, c)
}

// 获取QQ openId
func GetOpenId(info *PrivateInfo, c *gin.Context) {
	resp, err := http.Get(fmt.Sprintf("%s?access_token=%s", "https://graph.qq.com/oauth2.0/me", info.AccessToken))
	if err != nil {
		fmt.Println("GetOpenId Err", err.Error())
		return
	}
	defer resp.Body.Close()

	bs, _ := ioutil.ReadAll(resp.Body)
	body := string(bs)
	info.OpenId = body[45:77]

	GetUserInfo(info, c)
}

// 获取QQ用户信息
func GetUserInfo(info *PrivateInfo, c *gin.Context) {
	conf := lib.LoadServerConfig()
	params := url.Values{}
	params.Add("access_token", info.AccessToken)
	params.Add("openid", info.OpenId)
	params.Add("oauth_consumer_key", conf.AppId)

	uri := fmt.Sprintf("https://graph.qq.com/user/get_user_info?%s", params.Encode())
	resp, err := http.Get(uri)
	if err != nil {
		fmt.Println("GetUserInfo Err:", err.Error())
		return
	}
	defer resp.Body.Close()

	bs, _ := ioutil.ReadAll(resp.Body)

	LoginSucceed(string(bs), info.OpenId, c)
}

// 登录成功 处理登录
func LoginSucceed(userInfo, openId string, c *gin.Context) {
	var qUserInfo QUserInfo
	//将数据转为结构体
	if err := json.Unmarshal([]byte(userInfo), &qUserInfo); err != nil {
		fmt.Println("转换json失败", err.Error())
		return
	}

	//创建一个token
	hashToken := util.EncodeMd5("token" + string(time.Now().Unix()) + openId)
	//存入redis
	if err := lib.SetKey(hashToken, openId, 24*3600); err != nil {
		fmt.Println("Redis Set Err:", err.Error())
		return
	}
	//设置cookie
	c.SetCookie("Token", hashToken, 3600*24, "/", "/", false, true)

	if ok := model.QueryUserExists(openId); ok { //用户存在直接登录
		//登录成功重定向到首页
		c.Redirect(http.StatusMovedPermanently, "/cloud/index")
	} else {
		model.CreateUser(openId, qUserInfo.Nickname, qUserInfo.FigureUrlQQ)
		//登录成功重定向到首页
		c.Redirect(http.StatusMovedPermanently, "/cloud/index")
	}
}

// 退出登录
func Logout(c *gin.Context) {
	token, err := c.Cookie("Token")
	if err != nil {
		fmt.Println("cookie", err.Error())
	}

	if err := lib.DelKey(token); err != nil {
		fmt.Println("Del Redis Err:", err.Error())
	}

	c.SetCookie("Token", "", 0, "/", "pyxgo.cn", false, false)
	c.Redirect(http.StatusFound, "/")
}

func randomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}

	return string(s)
}
