var socket = new ReconnectingWebSocket("ws://" + location.host.split(":")[0] + ":9999/");
socket.timeoutInterval = 5000;
socket.reconnectInterval = 3000;

socket.onopen = function() {
	console.log("open");
};

socket.onclose = function(event) {
	console.log("error");
};

socket.onmessage = function(event) {
	if(event && event.data) {
		console.log(event.data);
	}
};

socket.onerror = function(error) {
	console.error("ws error: " + error.message);
};

$("form").submit(function() {
	$(this).find("input[name=csrf-token]").val(Cookies.get("csrf-token"));
	$.post($(this).attr("action"), $(this).serialize())
		.done(function(data) {
			console.log("OK");
		})
		.fail(function(xhr) {
			console.log(xhr.responseText);
		});
	return false;
});
