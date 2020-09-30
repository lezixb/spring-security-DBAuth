package com.xardtek.demo.student;

import com.xardtek.demo.models.Student;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/students")

public class StudentController {

    private static final List<Student> STUDENTS= Arrays.asList(
            new Student(1,"user Name-1"),
            new Student(2,"user Name-2"),
            new Student(3,"user Name-3"),
            new Student(4,"user Name-4")
    );

    @GetMapping
    public List<Student> getAllStudents(){
        return STUDENTS;
    }

}
