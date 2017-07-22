<?php
header("Content-Type:text/html;charset=utf8");
if(!isset($_POST['sign_in']))
{
    echo "Access denied for without sign in";
}
$connect=mysqli_connect("localhost","root","root","ssl");
$username = $_POST["username"];
$pass = $_POST["password"];
$password=md5($pass);

$sql = "SELECT * FROM user ";
$result=mysqli_query($connect,$sql);
if(mysqli_num_rows($result)>0)
{

  $i=1;
  while($i<=mysqli_num_rows($result))
  {
  $row=mysqli_fetch_assoc($result);
  $u=$row["username"];
  $psw=$row["psw"];

  if($u==$username)
  {
    //echo "hello，用户名合法存在";
    if($psw==$password)
    {
      //echo "\nsuccess";
      //echo "\n恭喜你成功登录，朋友".$row["username"];
      $connect->close();
      Include ("login_success.html");
    }
    else {
        echo "\n密码错误啊亲，快想想正确密码";
    }
  }
  $i++;
  }
}
else{
  echo "\nsorry，你还是先注册吧";
}
$connect->close();

