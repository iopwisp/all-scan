package org.example.redoor;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@EnableAsync
@SpringBootApplication
public class RedoorApplication {

    public static void main(String[] args) {
        SpringApplication.run(RedoorApplication.class, args);
    }
}
