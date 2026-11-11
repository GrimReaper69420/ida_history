HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            padding: 30px;
            background: #0f1117;
            color: #e6e6e6;
            font-family: Arial, Helvetica, sans-serif;
        }

        .container {
            max-width: 1400px;
            margin: auto;
        }

        header {
            margin-bottom: 35px;
            padding-bottom: 20px;
            border-bottom: 1px solid #30343d;
        }

        h1 {
            margin: 0;
            color: #ffffff;
        }

        .category {
            margin-bottom: 35px;
            background: #171a21;
            border: 1px solid #2b303a;
            border-radius: 10px;
            overflow: hidden;
        }

        .category-header {
            padding: 15px 20px;
            background: #1d212a;
            border-bottom: 1px solid #2b303a;
        }

        .category-header h2 {
            margin: 0;
            color: #66b3ff;
            font-size: 20px;
        }

        .address {
            margin: 15px;
            border: 1px solid #303640;
            border-radius: 8px;
            overflow: hidden;
        }

        .address-header {
            padding: 10px 15px;
            background: #20242d;
            color: #ffcc66;
            font-family: monospace;
            font-weight: bold;
        }

        .event {
            padding: 15px;
            border-top: 1px solid #303640;
        }

        .field {
            display: flex;
            padding: 6px 0;
        }

        .field-name {
            width: 180px;
            flex-shrink: 0;
            color: #8fb3d9;
            font-weight: bold;
        }

        .field-value {
            color: #dddddd;
            white-space: pre-wrap;
            word-break: break-word;
            font-family: monospace;
        }

        .event + .event {
            border-top: 1px dashed #3a3f49;
        }

        .empty {
            padding: 20px;
            color: #888;
        }
    </style>
</head>

<body>
    <div class="container">
        <header>
            <h1>{{ title }}</h1>
        </header>

        {% for category, addresses in events.items() %}
        <section class="category">
            <div class="category-header">
                <h2>{{ category }}</h2>
            </div>

            {% if addresses %}
                {% for address, event_list in addresses.items() %}
                <div class="address">
                    <div class="address-header">
                        {{ "%#x"|format(address) }}
                    </div>

                    {% for event in event_list %}
                    <div class="event">
                        {% for field, value in event.items() %}
                        <div class="field">
                            <div class="field-name">
                                {{ field }}
                            </div>

                            <div class="field-value">
                                {{ value }}
                            </div>
                        </div>
                        {% endfor %}
                    </div>
                    {% endfor %}
                </div>
                {% endfor %}
            {% else %}
                <div class="empty">
                    No events recorded.
                </div>
            {% endif %}
        </section>
        {% endfor %}
    </div>
</body>
</html>
"""