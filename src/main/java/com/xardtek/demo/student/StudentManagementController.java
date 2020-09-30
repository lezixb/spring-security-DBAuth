package com.xardtek.demo.student;


import com.xardtek.demo.models.Student;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;



@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {


    private static final List<Student> STUDENTS= Arrays.asList(
            new Student(1,"user Name-1"),
            new Student(2,"user Name-2"),
            new Student(3,"user Name-3"),
            new Student(4,"user Name-4")
    );
    /*
    * PreAuthorize Anotation is code level role/access based permission for API resources
    *  hasRole('ROLE_') hasAnyRole('ROLE_') hasAuthority('Permission') hasAnyAuthority('Permission')
    * */

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")
    public List<Student> getAllStudents(){
        return STUDENTS;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('student:write')")
    public void registerNewStudent(@RequestBody Student student){
        System.out.println("Inside registerNewStudent Student:::"  + student);
        System.out.println(student);
    }

    @DeleteMapping(path = "{studentId}")
    @PreAuthorize("hasAuthority('student:write')")
    public void deleteStudent(@PathVariable("studentId") Integer studentId){
        System.out.println("Inside deleteStudent Student:::" + studentId);
        System.out.println(studentId);
    }

    @PutMapping(path = "{studentId}")
    @PreAuthorize("hasAuthority('student:write')")
    public void updateStudent(@PathVariable("studentId") Integer studentId, @RequestBody Student student){
        System.out.println("Inside Update Student:::"+ student);
        System.out.println(String.format("%s %s", studentId,student));
    }
}
