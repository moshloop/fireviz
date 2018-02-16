package pkg

import (
	"os"
	"fmt"
)

func LogError(msg string, args ... interface{}) {
	os.Stderr.WriteString("ERROR: "  +fmt.Sprintf(msg, args...) + "\n")
}

func LogInfo(msg string, args ... interface{}) {
	os.Stderr.WriteString( fmt.Sprintf(msg, args...) + "\n")
}
