from api_app.visualizers_manager.visualizers.all_ip_visualizers import IPReputationServices

# Example usage
ip_service = IPReputationServices()
ip_to_check = "192.168.1.0"
ip_service.check_ip_reputation(ip_to_check)
ip_service.visualize_reputation(ip_to_check)
