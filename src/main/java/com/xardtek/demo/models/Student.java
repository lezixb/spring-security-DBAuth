package com.xardtek.demo.models;

public class Student {

    private  Integer studentId;
    private  String studentName;


    public Student() {
        super();
    }

    public Student( Integer studentId, String studentName) {
        this.studentId = studentId;
        this.studentName = studentName;
    }

    public Integer getStudentId() {
        return studentId;
    }

    public String getStudentName() {
        return studentName;
    }
}
