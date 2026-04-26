from .sqli import check_sqli
from .xss import check_xss
from .configs import check_configs

# Единый список всех проверок. 
# Оркестратору останется просто пробежаться по нему циклом.
ALL_CHECKS = [check_sqli, check_xss, check_configs]