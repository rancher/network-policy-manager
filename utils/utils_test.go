package utils

import (
	"testing"

	"github.com/rancher/log"
)

func TestConvertToLocalLink(t *testing.T) {
	log.SetLevelString("debug")
	inputLink := "region1/env1/stack1/service1"

	isLocal, localLink := ConvertToLocalLink(inputLink, "region1", "env1")
	if !isLocal {
		t.Fail()
	}

	if localLink != "stack1/service1" {
		t.Fail()
	}

	inputLink = "env1/stack1/service1"

	isLocal, localLink = ConvertToLocalLink(inputLink, "region1", "env1")
	if !isLocal {
		t.Fail()
	}

	if localLink != "stack1/service1" {
		t.Fail()
	}

}
