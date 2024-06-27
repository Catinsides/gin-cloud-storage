package model

import (
	"file-store/model/mysql"
	"time"
)

// 用户表
type User struct {
	Id           int
	OpenId       string
	FileStoreId  int
	UserName     string
	Password     string
	Salt         string
	RegisterTime time.Time
	ImagePath    string
}

// 创建用户并新建文件仓库
func CreateUser(openId, username, image string) {
	user := User{
		OpenId:       openId,
		FileStoreId:  0,
		UserName:     username,
		RegisterTime: time.Now(),
		ImagePath:    image,
	}
	mysql.DB.Create(&user)

	fileStore := FileStore{
		UserId:      user.Id,
		CurrentSize: 0,
		MaxSize:     1048576,
	}
	mysql.DB.Create(&fileStore)

	user.FileStoreId = fileStore.Id
	mysql.DB.Save(&user)
}

func CreateUserCommon(openId, username, password, salt, image string) {
	user := User{
		OpenId:       openId,
		FileStoreId:  0,
		UserName:     username,
		Password:     password,
		Salt:         salt,
		RegisterTime: time.Now(),
		ImagePath:    image,
	}
	mysql.DB.Create(&user)

	fileStore := FileStore{
		UserId:      user.Id,
		CurrentSize: 0,
		MaxSize:     1048576,
	}
	mysql.DB.Create(&fileStore)

	user.FileStoreId = fileStore.Id
	mysql.DB.Save(&user)
}

// 查询判断用户是否存在
func QueryUserExists(openId string) bool {
	var user User
	mysql.DB.Find(&user, "open_id = ?", openId)
	return user.Id != 0
}

func QueryUserExistsByName(username string) bool {
	var user User
	mysql.DB.Find(&user, "user_name = ?", username)
	return user.Id != 0
}

func QueryUserById(id int) (user User) {
	mysql.DB.Find(&user, "id = ?", id)
	return
}

func QueryUserByName(username string) (user User) {
	mysql.DB.Find(&user, "user_name = ?", username)
	return
}

// 根据openId查询用户
func GetUserInfo(openId interface{}) (user User) {
	mysql.DB.Find(&user, "open_id = ?", openId)
	return
}
