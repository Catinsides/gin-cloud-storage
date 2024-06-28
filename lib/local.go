package lib

import (
	"os"
)

func DownloadLocal(fileName, fileType string) ([]byte, error) {
	conf := LoadServerConfig()
	return os.ReadFile(conf.UploadLocation + fileName + fileType)
}
