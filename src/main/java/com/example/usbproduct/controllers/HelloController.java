package com.example.usbproduct.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/product/hello")
public class HelloController {

    @PreAuthorize("hasAnyAuthority('USER')")
    @GetMapping("/user")
    public String greetUser() {
        return "Hello user...";
    }

    @PreAuthorize("hasAnyAuthority('ADMIN')")
    @GetMapping("/admin")
    public String greetAdmin() {
        return "Hello admin...";
    }
}
