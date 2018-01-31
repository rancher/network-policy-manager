package utils

import (
	"strings"
)

// ConvertToLocalLink checks if the given link is local and then converts
// to local format
// Valid local links:
// localRegionName/envName/stackName/serviceName
// envName/stackName/serviceName
func ConvertToLocalLink(link, regionName, envName string) (bool, string) {
	words := strings.Split(link, "/")
	if len(words) == 4 {
		splits := strings.SplitAfter(link, regionName+"/"+envName+"/")
		//log.Debugf("splits: %v", splits)
		if len(splits) == 2 {
			return true, splits[1]
		}
	} else if len(words) == 3 {
		splits := strings.SplitAfter(link, envName+"/")
		//log.Debugf("splits: %v", splits)
		if len(splits) == 2 {
			return true, splits[1]
		}
	}
	return false, ""
}
