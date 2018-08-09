<?php
require_once 'includes.php';
if ($auth->isLoggedIn()) {
    header("Location: " . "index.php");
    die();
}

echo <<<EOD
<script>
document.addEventListener('DOMContentLoaded', function() {
    document.querySelector('form').addEventListener('submit', function(e) {
        let form = e.target,
            body = {},
            formData = new FormData(document.querySelector('form'));
        formData.forEach((value, key) => { body[key] = value; });
        fetch(
          form.getAttribute('action'),
          {
            method: 'POST',
            body: JSON.stringify(body),
            cache: 'no-cache',
            headers: {
               'content-type': 'application/json'
            }
          }
        ).then(res => res.json()).catch(v=>v).then(data => {
            console.log(data);
            if(data === 'ok')
            {
                window.location.href = 'index.php';
            }
            else
            {
                alert('Fehler');
            }
        }); 
      e.preventDefault();
    });
});
</script>

<form action="login_controller.php" method="post">
	<input type="text" name="email" value="" required="required" placeholder="E-Mail-Adresse" />
	<input type="password" name="password" value="" required="required" placeholder="Passwort" />
	<input type="submit" name="login" value="Einloggen" />
</form>
EOD;
