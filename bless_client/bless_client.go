package main

import (
    "os"
    "log"
    "os/user"
    "io/ioutil"
    "encoding/json"
    "github.com/aws/aws-sdk-go/aws"
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/service/lambda"
)

func check(e error) {
    if e != nil {
        log.Fatal(e.Error())
    }
}

func main() {
    args := os.Args[1:]
    if len(args) != 6 {
        log.Fatal("Usage: bless_client region lambda_function_name bastion_ip bastion_command <id_rsa.pub to sign> <output id_rsa-cert.pub>")
    }

    region, lambda_function_name, bastion_ip, bastion_command, public_key_filename, certificate_filename := args[0], args[1], args[2], args[3], args[4], args[5]

    current_user, user_err := user.Current()
    check(user_err)

    public_key, read_err := ioutil.ReadFile(public_key_filename)
    check(read_err)

    payload := map[string]string{"bastion_user": current_user.Username, "bastion_user_ip": bastion_ip,
                                 "remote_username": current_user.Username, "bastion_ip": bastion_ip,
                                 "command": bastion_command, "public_key_to_sign": string(public_key)}
    payload_json, marshal_err := json.Marshal(payload)
    check(marshal_err)

    log.Println("Executing in " + region)

    sess := session.Must(session.NewSession())
    svc := lambda.New(sess, &aws.Config{
        Region: aws.String(region),
    })

    params := &lambda.InvokeInput{
        FunctionName: aws.String(lambda_function_name),
        InvocationType: aws.String("RequestResponse"),
        LogType: aws.String("None"),
        Payload: []byte(payload_json),
    }
    resp, invoke_err := svc.Invoke(params)
    check(invoke_err)

    if int(*resp.StatusCode) != 200 {
        log.Fatal("Error creating cert.")
    }

    cert_err := ioutil.WriteFile(certificate_filename, resp.Payload[1:len(resp.Payload) - 3], 0600)
    check(cert_err)

    log.Println("Wrote Certificate to: " + certificate_filename)
}