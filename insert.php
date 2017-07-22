<?php
	header("Content-Type:text/html;charset=utf8");
	if(!isset($_POST['submit'])){
		exit("Wrong!");
	}
	$name=$_POST['name'];
	$email=$_POST['email'];
	$usr=$_POST['username'];
	$psw=md5($_POST['psw']);

	include('connect_mysql.php');//连接数据库

	$sql_Ist="Insert into user(name,email,username,psw) values ('$name','$email','$usr','$psw')";
	$pdo->exec($sql_Ist) or die(print_r($pdo->errorinfo(),true));
	
	$pdo=null;
?>
