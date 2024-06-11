# api_app/visualizers_manager/visualizers/__init__.py

class Visualizer:
    def __init__(self):
        pass

    def display_data(self, data):
        # Simple method to display data
        print("Displaying Data:")
        for key, value in data.items():
            print(f"{key}: {value}")
