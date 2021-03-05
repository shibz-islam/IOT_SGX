//
// Created by shihab on 3/18/20.
//

#include "EmailManager.h"
#include "email.h"

void sendEmail(std::string from, std::string to, std::string cc, std::string subject, std::string body, std::string pass){
    Email e;
    int curlError = 0;
    // e.dump();

    if(from.length() == 0 || pass.length() == 0)
    {
        //ToDo: fetch email and password from file
    }

    e.setFrom(from);
    e.setTo(to);
    e.setSubject(subject);
    e.setCc(cc);
    e.setBody(body);

    e.setSMTP_host("smtps://smtp.gmail.com:465");
    e.setSMTP_username(from);
    e.setSMTP_password("dml12345");

    //e.addAttachment("/home/matthew/Git Projects/Very-Simple-SMTPS/email.cpp");
    // e.addAttachment("email.h");
    // e.addAttachment("main.cpp");

    e.constructEmail();
    e.dump();

    curlError = e.send();

    if (curlError){
        std::cout << "Error sending email!" << std::endl;
    }

    else{
        std::cout << "Email sent successfully!" << std::endl;
    }
}
