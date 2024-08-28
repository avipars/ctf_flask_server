
// prepare the data for the line chart
const dateLabels = [{% for data in sales_data %}"{{ data.date }}"{% if not loop.last %}, {% endif %} {% endfor %}];
const salesData = [{% for data in sales_data %}{ { data.sales } } {% if not loop.last %}, {% endif %} {% endfor %}];
const profitData = [{% for data in sales_data %}{ { data.profit } } {% if not loop.last %}, {% endif %} {% endfor %}];
const reachData = [{% for data in sales_data %}{ { data.reach } } {% if not loop.last %}, {% endif %} {% endfor %}];

// Bar Chart
const barCtx = document.getElementById('barChart').getContext('2d');
new Chart(barCtx, {
    type: 'bar',
    data: {
        labels: dateLabels,// x-axis labels
        datasets: [{
            label: 'Profit',
            data: profitData,
            backgroundColor: 'rgba(75, 192, 192, 0.5)',
            borderColor: 'rgba(75, 192, 192, 1)',
            borderWidth: 1,
        }, {
            label: 'Sales',
            data: salesData,
            backgroundColor: 'rgba(240, 130, 220 , 0.5)',
            borderColor: 'rgba(240, 130, 220 , 1)',
            borderWidth: 1
        },
        ]
    },
    options: {
        scales: {
            x: {
                title: {
                    display: true,
                    text: 'Date'
                }
            },
            y: {
                title: {
                    display: true,
                    text: 'Sales'
                }
            }

        }
    }
});

const ctx = document.getElementById('lineChart').getContext('2d');
const lineChart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: dateLabels,
        datasets: [
            {
                label: 'Reach',
                data: reachData,
                backgroundColor: 'rgba(209, 229, 45 , 0.5)',
                borderColor: 'rgba(209, 229, 45 , 1)',
                borderWidth: 1
            },
            {
                label: 'Profit',
                data: profitData,
                backgroundColor: 'rgba(75, 192, 192, 0.5)',
                borderColor: 'rgba(75, 192, 192, 1)',
                borderWidth: 1
            },

        ]
    },
    options: {
        responsive: true,
        scales: {
            x: {
                beginAtZero: true
            },
            y: {
                beginAtZero: true
            }
        }
    }
});