<html>
<body>

<script type="text/javascript">
socket= new WebSocket('ws://<?php echo gethostname(); ?>:8080');
socket.onopen= function() {
    socket.send('hello');
};
socket.onmessage= function(s) {
    alert('got reply '+s.data);
};
</script>
</body>
</html>

