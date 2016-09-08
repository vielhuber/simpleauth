<?php
require_once('functions.php');

if( auth_is_user_logged_in() ) { header("Location: " . "dashboard.php"); die(); }
?>
<script type="text/javascript" src="https://ajax.googleapis.com/ajax/libs/jquery/3.1.0/jquery.min.js"></script>
<script type="text/javascript">
<!--
$(document).ready(function() {
    if( $('#auth_form').length > 0 ) {
        $('#auth_form').submit(function() {
            var self = this;
            $.ajax({
                method: $(self).attr('method'),
                url: $(self).attr('action'),
                data: $(self).serialize()
            }).done(function(data) {
                if( data == 'ok' ) {
                    window.location.href = 'dashboard.php';
                }
                else {
                    $(self).find('.message').remove();
                    $(self).prepend('<div class="message">Username oder Passwort falsch</div>');
                }
            });
            return false;
        });
    }
});
-->
</script>
<form id="auth_form" action="login_controller.php" method="post">
	<input type="text" name="username" value="" required="required" placeholder="Username" />
	<input type="password" name="password" value="" required="required" placeholder="Passwort" />
	<input type="submit" name="login" value="Einloggen" />
</form>