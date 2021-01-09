package main

import (
	"fmt"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/persist"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	"log"
)

func main(){
	adapter := fileadapter.NewAdapter("./config/basic_policy.csv")

	type testUnion struct{
		sub string
		obj1 string
		obj2 string
		obj3 string
		act string
	}
	var testOriginArray = []testUnion{
		{"user::10118", "AI","AI_COURSE_SCHEDULING","gg", "LIST"},
		{"user::101189", "AI","AI_COURSE_SCHEDULING","gg", "LIST"},
	}

	for _, v := range testOriginArray{
		// casbin enforces policy
		var logString = fmt.Sprintf("%s (%s %s %s) %s<--->", v.sub, v.obj1, v.obj2, v.obj3, v.act)
		ok, err := enforceTest(v.sub, v.obj1, v.obj2, v.obj3, v.act, adapter)
		if err != nil {
			log.Println(logString, err)
			continue
		}
		if !ok {
			log.Println(logString + " not pass\n")
			continue
		}
		log.Println(logString + " pass\n")
	}
}

// key1 request
// key2 policy
func KeyMatch(key1 string, key2 string) bool {

	if key2 == "*"{
		return true
	}
	if key1 == key2{
		return true
	}
	return false
}

// --------------------------------------------------------------------- //

func KeyMatchFunc(args ...interface{}) (interface{}, error) {
	name1 := args[0].(string)
	name2 := args[1].(string)

	return (bool)(KeyMatch(name1, name2)), nil
}

func enforceTest(sub string, obj1 string, obj2 string, obj3 string, act string, adapter persist.Adapter) (bool, error) {
	//log.Println(sub, obj1, obj2, obj3, act)
	enforcer, err := casbin.NewEnforcer("./config/rbac_model.conf", adapter)
	if err != nil {
		return false, fmt.Errorf("failed to create casbin enforcer: %w", err)
	}
	// Load policies from DB dynamically
	err = enforcer.LoadPolicy()
	if err != nil {
		return false, fmt.Errorf("failed to load policy from DB: %w", err)
	}
	enforcer.AddFunction("my_func", KeyMatchFunc)
	//enforcer.EnableLog(true)

	ok, err := enforcer.Enforce(sub, obj1, obj2, obj3, act)
	//fmt.Println(ok, err)
	return ok, err
}
