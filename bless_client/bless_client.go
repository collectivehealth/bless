package main

import (
    "os"
    "fmt"
    "io/ioutil"
    "encoding/json"
    "github.com/aws/aws-sdk-go/aws"
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/service/lambda"
    "reflect"
)

func check(e error) {
    if e != nil {
        panic(e)
    }
}

func main() {
    args := os.Args[1:]
    if len(args) != 9 {
        fmt.Println(
            `Usage: bless_client.py region lambda_function_name bastion_user bastion_user_ip
             remote_username bastion_ip bastion_command <id_rsa.pub to sign>
             <output id_rsa-cert.pub>`)
        os.Exit(1)
    }

    region, lambda_function_name, bastion_user, bastion_user_ip, remote_username, bastion_ip, bastion_command, public_key_filename, certificate_filename := args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8]

    fmt.Println(region, lambda_function_name, bastion_user, bastion_user_ip, remote_username, bastion_ip, bastion_command, public_key_filename, certificate_filename)

    public_key, err := ioutil.ReadFile(public_key_filename)
    check(err)
    fmt.Print(string(public_key))
    fmt.Println(reflect.TypeOf(public_key))

    payload := map[string]string{"bastion_user": bastion_user, "bastion_user_ip": bastion_user_ip,
                                 "remote_username": remote_username, "bastion_ip": bastion_ip,
                                 "command": bastion_command, "public_key_to_sign": string(public_key)}
    payload_json, _ := json.Marshal(payload)
    fmt.Println(string(payload_json))

    fmt.Println("Executing:")
    sess := session.Must(session.NewSession())
    svc := lambda.New(sess)

    params := &lambda.InvokeInput{
        FunctionName: aws.String(lambda_function_name),
        InvocationType: aws.String("RequestResponse"),
        LogType: aws.String("None"),
        Payload: []byte(payload_json),
    }
    resp, err := svc.Invoke(params)

    if err != nil {
        fmt.Println(err.Error())
        os.Exit(1)
    }

    fmt.Println(reflect.TypeOf(*resp.StatusCode))

    if int(*resp.StatusCode) != 200 {
        fmt.Println("Error creating cert.")
        os.Exit(1)
    }

    cert := string(resp.Payload[:])
    fmt.Println(cert)

    cert_err := ioutil.WriteFile(certificate_filename, resp.Payload[1:len(resp.Payload) - 3], 0600)
    check(cert_err)

    fmt.Println("Wrote Certificate to: " + certificate_filename)
}