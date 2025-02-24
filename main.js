let keyScore1 = "Toan";
let keyScore2 = "Tin";
let Student = function(id,name,age,score1,score2){
    this.id = id;
    this.name = name;
    this.age = age;
    this.scores={
        [keyScore1]: score1,
        [keyScore2]: score2
    }
    this.getInfo = function(){
        return id;
    }
}
let students = [];
students.push(new Student(4,"Tung",17,9,9));
students.push(new Student(3,"Toan",18,2,2));
students.push(new Student(2,"Tien",18,2,9));
students.push(new Student(1,"Tuan",18,3,4));
// let result = [];
// for (const student of students) {
//     if(student.scores[keyScore1]+student.scores[keyScore2]>=16){
//         result.push("Gioi");
//     }else{
//         if(student.scores[keyScore1]+student.scores[keyScore2]>=13){
//             result.push("Kha");
//         }else{
//             if (student.scores[keyScore1]+student.scores[keyScore2]>=8) {
//                 result.push("TB");
//             } else {
//                 result.push("Kem");
//             }
//         }
//     }
// }
let result = students.map(
    function(student){
    if(student.scores[keyScore1]+student.scores[keyScore2]>=16){
        return "Gioi";
    }else{
        if(student.scores[keyScore1]+student.scores[keyScore2]>=13){
            return "Kha";
        }else{
            if (student.scores[keyScore1]+student.scores[keyScore2]>=8) {
                return "TB";
            } else {
                return "Kem";
            }
        }
    }
    }
);

// let sum = 0;
// for (const student of students) {
//     sum+=student.age;
// }

let max = students.reduce(function(max,student){
    return max<student.age?student.age:max;
},students[0].age)
let sum = students.reduce(function(sum,student){
    return sum+=student.age;
},0)

// let Duoi18 = [];
// for (const student of students) {
//     if(student.age<18){
//         Duoi18.push(student);
//     }
// }
let Duoi18 = students.filter(function(student){
    return student.age<18;
})

let checkDup = students.some(
    function(student){
        return student.scores.score1+student.scores.score1<8;
    }
)
let checkQUaMon = students.every(
    function(student){
        return student.scores.score1+student.scores.score1>8;
    }
)

students.sort(Compare)

function Compare(student1,student2){
    if(student1.age==student2.age){
        return student1.id-student2.id;
    }
    return student1.age-student2.age;
}