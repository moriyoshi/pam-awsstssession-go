//build +cgo

// Copyright (c) 2020 Moriyoshi Koizumi
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
package main

// #cgo LDFLAGS: -lpam
// #include <string.h>
// #include <stdlib.h>
// #include <errno.h>
// #include <security/pam_modules.h>
//
// typedef const char ** const_charpp;
//
// size_t _GoStringLen(_GoString_ s);
// const char *_GoStringPtr(_GoString_ s);
//
// static int call_pam_conv_func(struct pam_conv *conv, int num_msgs, const struct pam_message **msg, struct pam_response **resp) {
//     return conv->conv(num_msgs, msg, resp, conv->appdata_ptr);
// }
import "C"

import (
	"context"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/aws/aws-sdk-go-v2/aws"
	// "github.com/aws/aws-sdk-go-v2/aws/awserr"
	"github.com/aws/aws-sdk-go-v2/aws/endpoints"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/aws/stscreds"
	// "github.com/aws/aws-sdk-go-v2/service/iam"
	// "github.com/aws/aws-sdk-go-v2/service/iam/iamiface"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/joho/godotenv"
)

const ttl = 120 * time.Second
const configFile = "/etc/pam_aws_sts_session.conf"
const envNamePrefixEndpointOverride = "AWS_ENDPOINT_OVERRIDES_"

var rootCtx = context.Background()

type GetEnvFunc func(string) string

func wrapEnvMap(envMap map[string]string) GetEnvFunc {
	return func(name string) string {
		if envMap != nil {
			v, ok := envMap[name]
			if ok {
				return v
			}
		}
		return ""
	}
}

type PAMModuleContext struct {
	DebugLevel             int
	Timeout                time.Duration
	GetEnv                 GetEnvFunc
	MFADeviceSerialNumber  string
	AssumedRoleTemplate    string
	SessionNameTemplate    string
	SessionDurationSeconds int64
}

func NewPAMModuleContext(getenv GetEnvFunc) *PAMModuleContext {
	retval := &PAMModuleContext{
		DebugLevel:             0,
		Timeout:                3 * time.Second,
		MFADeviceSerialNumber:  "UNKNOWN",
		AssumedRoleTemplate:    "arn:aws:iam::{accountId}:role/terminalAccess/{userName}",
		SessionNameTemplate:    "{userName}",
		SessionDurationSeconds: 900,
		GetEnv:                 getenv,
	}
	{
		v, err := strconv.Atoi(getenv("PAM_AWSSTSSESSION_GO_DEBUG"))
		if err == nil {
			retval.DebugLevel = v
		}
	}
	{
		v, err := time.ParseDuration(getenv("PAM_AWSSTSSESSION_GO_TIMEOUT"))
		if err == nil {
			retval.Timeout = v
		}
	}
	{
		v := getenv("PAM_AWSSTSSESSION_MFA_DEVICE_SERIAL_NUMBER")
		if v != "" {
			retval.MFADeviceSerialNumber = v
		}
	}
	{
		v := getenv("PAM_AWSSTSSESSION_GO_ASSUMED_ROLE_TEMPLATE")
		if v != "" {
			retval.AssumedRoleTemplate = v
		}
	}
	{
		v := getenv("PAM_AWSSTSSESSION_GO_SESSION_NAME_TEMPLATE")
		if v != "" {
			retval.SessionNameTemplate = v
		}
	}
	{
		v, err := strconv.Atoi(getenv("PAM_AWSSTSSESSION_SESSION_DURATION"))
		if err == nil {
			retval.SessionDurationSeconds = int64(v)
		}
	}
	return retval
}

func (c *PAMModuleContext) Log(msg ...interface{}) {
	if c.DebugLevel > 0 {
		fmt.Fprintln(os.Stderr, msg...)
	}
}

func boolVal(v string) bool {
	v = strings.ToLower(v)
	if v == "false" || v == "no" || v == "0" || v == "" {
		return false
	} else {
		return true
	}
}

func (c *PAMModuleContext) getEnvOfAny(names ...string) string {
	for _, name := range names {
		v := c.GetEnv(name)
		if v != "" {
			return v
		}
	}
	return ""
}

func (c *PAMModuleContext) envConfig(_ external.Configs) (external.Config, error) {
	var cfg external.EnvConfig

	creds := aws.Credentials{
		Source: external.CredentialsSourceName,
	}
	creds.AccessKeyID = c.getEnvOfAny("AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY")
	creds.SecretAccessKey = c.getEnvOfAny("AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY")
	if creds.HasKeys() {
		creds.SessionToken = c.getEnvOfAny("AWS_SESSION_TOKEN")
		cfg.Credentials = creds
	}

	cfg.ContainerCredentialsEndpoint = c.GetEnv("AWS_CONTAINER_CREDENTIALS_FULL_URI")
	cfg.ContainerCredentialsRelativePath = c.GetEnv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
	cfg.ContainerAuthorizationToken = c.GetEnv("AWS_CONTAINER_AUTHORIZATION_TOKEN")

	cfg.Region = c.getEnvOfAny("AWS_REGION", "AWS_DEFAULT_REGION")
	cfg.SharedConfigProfile = c.getEnvOfAny("AWS_PROFILE", "AWS_DEFAULT_PROFILE")

	cfg.SharedCredentialsFile = c.GetEnv("AWS_SHARED_CREDENTIALS_FILE")
	cfg.SharedConfigFile = c.GetEnv("AWS_CONFIG_FILE")

	cfg.CustomCABundle = c.GetEnv("AWS_CA_BUNDLE")

	cfg.WebIdentityTokenFilePath = c.GetEnv("AWS_WEB_IDENTITY_TOKEN_FILE")

	cfg.RoleARN = c.GetEnv("AWS_ROLE_ARN")
	cfg.RoleSessionName = c.GetEnv("AWS_ROLE_SESSION_NAME")

	if v := c.GetEnv("AWS_ENABLE_ENDPOINT_DISCOVERY"); v != "" {
		cfg.EnableEndpointDiscovery = aws.Bool(boolVal(v))
	}
	if v := c.GetEnv("AWS_S3_USE_ARN_REGION"); v != "" {
		cfg.S3UseARNRegion = aws.Bool(boolVal(v))
	}
	return cfg, nil
}

func (c *PAMModuleContext) GetAWSConfig() (cfg aws.Config, err error) {
	var ourConfigs external.Configs
	ourConfigs, _ = ourConfigs.AppendFromLoaders([]external.ConfigLoader{c.envConfig})
	stsAssumeRoleArn := c.GetEnv("AWS_STS_ASSUME_ROLE_ARN")
	if stsAssumeRoleArn != "" {
		cfg, err = ourConfigs.ResolveAWSConfig(external.DefaultAWSConfigResolvers)
		if err != nil {
			return
		}
		if c.DebugLevel > 1 {
			cfg.LogLevel = aws.LogDebug
		}
		sts := sts.New(cfg)
		cfg.Credentials = stscreds.NewAssumeRoleProvider(sts, stsAssumeRoleArn)
	} else {
		cfg, err = ourConfigs.ResolveAWSConfig(external.DefaultAWSConfigResolvers)
		if err != nil {
			return
		}
		if c.DebugLevel > 1 {
			cfg.LogLevel = aws.LogDebug
		}
	}

	resolver := endpoints.NewDefaultResolver()

	vars := map[string]string{
		"region": cfg.Region,
	}

	cfg.EndpointResolver = aws.EndpointResolverFunc(
		func(service, region string) (aws.Endpoint, error) {
			endpointTemplate := c.GetEnv(envNamePrefixEndpointOverride + strings.ToUpper(service))
			if endpointTemplate != "" {
				url, err := replacePlaceholders(endpointTemplate, vars)
				if err != nil {
					return aws.Endpoint{}, err
				}
				return aws.Endpoint{
					URL: url,
				}, nil
			} else {
				return resolver.ResolveEndpoint(service, region)
			}
		},
	)

	return
}

func envMapFromArgv(argc C.int, argv C.const_charpp) map[string]string {
	envMap := make(map[string]string)
	if argv == nil {
		return envMap
	}
	argp := (*[math.MaxInt32]*C.char)(unsafe.Pointer(argv))[:argc]
	for _, v := range argp {
		m, err := godotenv.Unmarshal(C.GoString(v))
		if err != nil {
			continue
		}
		for k, v := range m {
			envMap[k] = v
		}
	}
	return envMap
}

func composeGetEnv(a, b GetEnvFunc) GetEnvFunc {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	return func(k string) string {
		v := a(k)
		if v != "" {
			return v
		}
		return b(k)
	}
}

var pamErrorCodeToStringMap = map[int]string{
	C.PAM_BAD_ITEM:    "PAM_BAD_ITEM",
	C.PAM_BUF_ERR:     "PAM_BUF_ERR",
	C.PAM_PERM_DENIED: "PAM_PERM_DENIED",
	C.PAM_SUCCESS:     "PAM_SUCCESS",
	C.PAM_SYSTEM_ERR:  "PAM_SYSTEM_ERR",
	C.PAM_CONV_ERR:    "PAM_CONV_ERR",
	C.PAM_ABORT:       "PAM_ABORT",
}

type PAMError struct {
	code int
}

func (e *PAMError) Error() string {
	r, ok := pamErrorCodeToStringMap[e.code]
	if !ok {
		return "(unknown)"
	} else {
		return r
	}
}

type PAMMessage struct {
	Style   int
	Message string
}

type PAMResponse struct {
	Retcode int
	Value   string
}

func converse(pamh *C.pam_handle_t, messages []PAMMessage) ([]PAMResponse, error) {
	var conv *C.struct_pam_conv
	if c := C.pam_get_item(pamh, C.PAM_CONV, (*unsafe.Pointer)(unsafe.Pointer(&conv))); c != C.PAM_SUCCESS {
		return nil, &PAMError{int(c)}
	}

	msgBufSize := unsafe.Sizeof(C.struct_pam_message{}) * uintptr(len(messages))
	if msgBufSize/uintptr(len(messages)) < unsafe.Sizeof(C.struct_pam_message{}) {
		return nil, fmt.Errorf("out of memory")
	}
	msgBuf := C.malloc(C.size_t(msgBufSize))
	if msgBuf == nil {
		return nil, fmt.Errorf("out of memory")
	}
	defer C.free(msgBuf)
	msgBufP := (*[math.MaxInt32]C.struct_pam_message)(msgBuf)[:len(messages)]
	msgs := make([]*C.struct_pam_message, 0, len(messages))
	defer func() {
		for _, m := range msgs {
			C.free(unsafe.Pointer(m.msg))
		}
	}()
	for i, m := range messages {
		p := C.CString(m.Message)
		if p == nil {
			return nil, fmt.Errorf("out of memory")
		}
		msg := &msgBufP[i]
		msg.msg_style = C.int(m.Style)
		msg.msg = p
		msgs = append(msgs, msg)
	}
	resps := make([]*C.struct_pam_response, len(messages))
	c := C.call_pam_conv_func(conv, C.int(len(msgs)), &msgs[0], &resps[0])
	if c != C.PAM_SUCCESS {
		return nil, &PAMError{int(c)}
	}
	responses := make([]PAMResponse, len(resps))
	for i, r := range resps {
		responses[i] = PAMResponse{
			Retcode: int(r.resp_retcode),
			Value:   C.GoString(r.resp),
		}
		C.free(unsafe.Pointer(r.resp))
	}
	return responses, nil
}

func envFromPAM(pamh *C.pam_handle_t) GetEnvFunc {
	return func(k string) string {
		ck := C.CString(k)
		if ck == nil {
			return ""
		}
		defer C.free(unsafe.Pointer(ck))
		v := C.pam_getenv(pamh, ck)
		if v == nil {
			return ""
		}
		return C.GoString(v)
	}
}

func buildGetEnvFunc(pamh *C.pam_handle_t, argc C.int, argv C.const_charpp) GetEnvFunc {
	var f GetEnvFunc
	{
		envMap, err := godotenv.Read(configFile)
		if err == nil {
			f = composeGetEnv(wrapEnvMap(envMap), f)
		}
	}
	f = composeGetEnv(wrapEnvMap(envMapFromArgv(argc, argv)), f)
	if boolVal(f("PAM_AWSSTSSESSION_GO_USE_ENVS_FROM_PAM")) {
		f = composeGetEnv(envFromPAM(pamh), f)
	}
	return f
}

func getUser(pamh *C.pam_handle_t) (string, error) {
	var userP *C.char
	if c := C.pam_get_user(pamh, &userP, nil); c != C.PAM_SUCCESS {
		return "", &PAMError{int(c)}
	}
	return C.GoString(userP), nil
}

func handleSessionToken(pamh *C.pam_handle_t, flags C.int, argc C.int, argv C.const_charpp) bool {
	_ = NewPAMModuleContext(buildGetEnvFunc(pamh, argc, argv))
	userName, err := getUser(pamh)
	if err != nil {
		return false
	}
	fmt.Println(userName)
	return true
}

func pamPutEnv(pamh *C.pam_handle_t, name, value string) error {
	v := C.CString(fmt.Sprintf("%s=%s", name, value))
	if v == nil {
		return fmt.Errorf("out of memory")
	}
	defer C.free(unsafe.Pointer(v))
	c := C.pam_putenv(pamh, v)
	if c != C.PAM_SUCCESS {
		return &PAMError{int(c)}
	}
	return nil
}

//export pam_sm_authenticate
func pam_sm_authenticate(pamh *C.pam_handle_t, flags C.int, argc C.int, argv C.const_charpp) C.int {
	c := NewPAMModuleContext(buildGetEnvFunc(pamh, argc, argv))

	cfg, err := c.GetAWSConfig()
	if err != nil {
		c.Log("pam_sm_authenticate", err.Error())
		return C.PAM_AUTH_ERR
	}

	var accountId string
	var callingIdentity string
	var callingIdentityArn string

	stsClient := sts.New(cfg)
	{
		ctx, cancel := context.WithTimeout(rootCtx, c.Timeout)
		defer cancel()
		req := stsClient.GetCallerIdentityRequest(&sts.GetCallerIdentityInput{})
		resp, err := req.Send(ctx)
		if err != nil {
			c.Log("pam_sm_authenticate", err.Error())
			return C.PAM_AUTH_ERR
		}
		accountId = *resp.Account
		callingIdentity = *resp.UserId
		callingIdentityArn = *resp.Arn
	}

	userName, err := getUser(pamh)
	if err != nil {
		c.Log("pam_sm_authenticate", err.Error())
		return C.PAM_AUTH_ERR
	}
	resps, err := converse(pamh, []PAMMessage{
		{
			Style:   C.PAM_PROMPT_ECHO_ON,
			Message: "Enter MFA token code: ",
		},
	})
	if err != nil {
		c.Log("pam_sm_authenticate", err.Error())
		return C.PAM_AUTHINFO_UNAVAIL
	}

	vars := map[string]string{
		"userName":           userName,
		"accountId":          accountId,
		"callingIdentity":    callingIdentity,
		"callingIdentityArn": callingIdentityArn,
	}
	sessionName, err := replacePlaceholders(c.SessionNameTemplate, vars)
	if err != nil {
		c.Log("pam_sm_authenticate", err.Error())
		return C.PAM_AUTH_ERR
	}
	assumedRoleArn, err := replacePlaceholders(c.AssumedRoleTemplate, vars)
	if err != nil {
		c.Log("pam_sm_authenticate", err.Error())
		return C.PAM_AUTH_ERR
	}

	{
		ctx, cancel := context.WithTimeout(rootCtx, c.Timeout)
		defer cancel()
		req := stsClient.AssumeRoleRequest(&sts.AssumeRoleInput{
			DurationSeconds: &c.SessionDurationSeconds,
			RoleArn:         &assumedRoleArn,
			RoleSessionName: &sessionName,
			SerialNumber:    &c.MFADeviceSerialNumber,
			TokenCode:       &resps[0].Value,
		})
		resp, err := req.Send(ctx)
		if err != nil {
			c.Log("pam_sm_authenticate", err.Error())
			return C.PAM_AUTHINFO_UNAVAIL
		}

		err = pamPutEnv(pamh, "AWS_ASSUMED_ROLE_USER_ARN", *resp.AssumedRoleUser.Arn)
		if err != nil {
			c.Log("pam_sm_authenticate", err.Error())
			return C.PAM_AUTHINFO_UNAVAIL
		}
		err = pamPutEnv(pamh, "AWS_ASSUMED_ROLE_USER_ID", *resp.AssumedRoleUser.AssumedRoleId)
		if err != nil {
			c.Log("pam_sm_authenticate", err.Error())
			return C.PAM_AUTHINFO_UNAVAIL
		}
		err = pamPutEnv(pamh, "AWS_ACCESS_KEY", *resp.Credentials.AccessKeyId)
		if err != nil {
			c.Log("pam_sm_authenticate", err.Error())
			return C.PAM_AUTHINFO_UNAVAIL
		}
		err = pamPutEnv(pamh, "AWS_ACCESS_KEY_ID", *resp.Credentials.AccessKeyId)
		if err != nil {
			c.Log("pam_sm_authenticate", err.Error())
			return C.PAM_AUTHINFO_UNAVAIL
		}
		err = pamPutEnv(pamh, "AWS_SECRET_KEY", *resp.Credentials.SecretAccessKey)
		if err != nil {
			c.Log("pam_sm_authenticate", err.Error())
			return C.PAM_AUTHINFO_UNAVAIL
		}
		err = pamPutEnv(pamh, "AWS_SECRET_ACCESS_KEY", *resp.Credentials.SecretAccessKey)
		if err != nil {
			c.Log("pam_sm_authenticate", err.Error())
			return C.PAM_AUTHINFO_UNAVAIL
		}
		err = pamPutEnv(pamh, "AWS_SESSION_TOKEN", *resp.Credentials.SessionToken)
		if err != nil {
			c.Log("pam_sm_authenticate", err.Error())
			return C.PAM_AUTHINFO_UNAVAIL
		}
		err = pamPutEnv(pamh, "AWS_SESSION_EXPIRATION", fmt.Sprintf("%d", (*resp.Credentials.Expiration).Unix()))
		if err != nil {
			c.Log("pam_sm_authenticate", err.Error())
			return C.PAM_AUTHINFO_UNAVAIL
		}
	}

	return C.PAM_SUCCESS
}

//export pam_sm_setcred
func pam_sm_setcred(pamh *C.pam_handle_t, flags C.int, argc C.int, argv C.const_charpp) C.int {
	if handleSessionToken(pamh, flags, argc, argv) {
		return C.PAM_SUCCESS
	} else {
		return C.PAM_CRED_UNAVAIL
	}
}

//export pam_sm_acct_mgmt
func pam_sm_acct_mgmt(pamh *C.pam_handle_t, flags C.int, argc C.int, argv C.const_charpp) C.int {
	return C.PAM_SERVICE_ERR
}

//export pam_sm_open_session
func pam_sm_open_session(pamh *C.pam_handle_t, flags C.int, argc C.int, argv C.const_charpp) C.int {
	if handleSessionToken(pamh, flags, argc, argv) {
		return C.PAM_SUCCESS
	} else {
		return C.PAM_SESSION_ERR
	}
}

//export pam_sm_close_session
func pam_sm_close_session(pamh *C.pam_handle_t, flags C.int, argc C.int, argv C.const_charpp) C.int {
	return C.PAM_SUCCESS
}

//export pam_sm_chauthtok
func pam_sm_chauthtok(pamh *C.pam_handle_t, flags C.int, argc C.int, argv C.const_charpp) C.int {
	return C.PAM_SERVICE_ERR
}

func main() {
}
