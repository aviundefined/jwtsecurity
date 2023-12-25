package com.rachvik.security.demo;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class DemoController {

  @PostMapping("/echo")
  public ResponseEntity<String> echo(@RequestBody final String message) {
    return ResponseEntity.ok(message);
  }
}
