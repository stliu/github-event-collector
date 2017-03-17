package com.easemob.stliu.github.rest;

import com.easemob.stliu.github.util.GithubAuthChecker;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.annotation.PostConstruct;

import lombok.extern.slf4j.Slf4j;

/**
 * 接收github的web hook消息, 具体消息结构参考 https://developer.github.com/webhooks/
 *
 * @author stliu @ apache.org
 */
@RestController
@Slf4j
public class GithubWebhookController {

    @Value("${github.webhook.secret:}")
    private String githubWebhookSecret;
    private GithubAuthChecker authChecker;
    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private MongoTemplate mongoTemplate;

    @PostConstruct
    public void init() throws InvalidKeyException, NoSuchAlgorithmException {
        if (!StringUtils.isEmpty(githubWebhookSecret)) {
            authChecker = new GithubAuthChecker(githubWebhookSecret);
            log.info("checking github event signature is enabled");
        }
    }

    @PostMapping(value = "/github/webhook", consumes = "application/json", produces = "application/json")
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<String> githubWebhookEvents(
            @RequestHeader("X-GitHub-Event") String event,
            @RequestHeader("X-GitHub-Delivery") String deliveryId,
            @RequestHeader(value = "X-Hub-Signature", required = false) String signature,
            @RequestBody String payload) {


        if (authChecker != null) {
            boolean success = authChecker.checkSignature(signature, payload);
            if (!success) {
                log.warn("security issue, security {} doesn't match with payload {}", signature, payload);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("{\"message\":\"signature doesn't match\"}");
            }
        }

        mongoTemplate.save(payload, "github");

        return ResponseEntity.ok("{ \"message\": \"Successfully processed update\" }\n");


    }
}
