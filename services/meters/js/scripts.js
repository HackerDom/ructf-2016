var labels = []
for (var i = 0; i < 300 ; ++i)
	labels.push('')

function draw(id, data) {
	var div = document.getElementById(id);
	var canvas = document.createElement('canvas');
	canvas.width = div.clientWidth;
	canvas.height = div.clientHeight;
	div.appendChild(canvas);
	var context = div.childNodes[0].getContext('2d');
	var chart = new Chart(context, {
		type: 'line',
		data: {
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
		},
		options: {
			legend: {
				display: false
			},
			elements: {
				point: {
					radius: 1
				}
			},
			scales: {
				yAxes: [{
					ticks: {
						beginAtZero: false
					}
				}]
			},
			animation: {
				duration: 0
			}
		}
	});
	setTimeout(chart.update, 0.5);
}
