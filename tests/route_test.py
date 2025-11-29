import unittest
import json
import os
from singbox2proxy import SingBoxProxy

class TestSingBoxRoute(unittest.TestCase):
    def test_route_config(self):
        route_config = {
            "rules": [
                {
                    "domain": ["google.com"],
                    "outbound": "proxy"
                },
                {
                    "domain": ["baidu.com"],
                    "outbound": "direct"
                }
            ]
        }
        
        # Initialize proxy with route config
        # Use a dummy link for config
        proxy = SingBoxProxy("socks://127.0.0.1:1080", route=route_config, config_only=True)
        
        # Generate config
        config_path = proxy.create_config_file()
        
        try:
            with open(config_path, "r") as f:
                config = json.load(f)
            
            self.assertIn("route", config)
            self.assertEqual(config["route"], route_config)
            
        finally:
            if os.path.exists(config_path):
                os.remove(config_path)

if __name__ == "__main__":
    unittest.main()
