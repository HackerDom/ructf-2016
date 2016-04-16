function draw(id, data) {
	setTimeout(function(){ drawInternal(id, data)}, 0.1);
}

function drawInternal(id, data) {
	var div = document.getElementById(id);
	var canvas = document.createElement('canvas');
	canvas.width = div.clientWidth;
	canvas.height = div.clientHeight;
	div.appendChild(canvas);
	var context = div.childNodes[0].getContext('2d');
	data = CreateData(data);
	var chart = new Chart(context, {
		type: 'line',
		data: data,
		options: {
			legend: {
				display: false
			},
			elements: {
				point: {
					radius: 1
				}
			}
		}
	});
	chart.update();
}

function CreateData(data) {
	var labels = [];
	for (var i = 0; i < 300 ; ++i)
		labels.push('')
	return {
		labels: labels,
		datasets: [
			{
				label: '',
				fill: true,
				backgroundColor: 'rgba(255, 255, 200, 0.5)',
				borderColor: 'rgba(255, 255, 170, 0.5)',
				pointBackgroundColor: 'rgba(255, 255, 85, 0.5)',
				pointBorderWidth: 0,
				data: data
			}
		]
	}
}
