from locust import HttpUser, task, between

class APIUser(HttpUser):
    wait_time = between(1, 3)

    @task(3)
    def health_check(self):
        self.client.get("/api/v1/health/")

    @task(1)
    def nests_unauth(self):
        # Even if 401, it tests the application overhead & DB 
        with self.client.get("/api/v1/nests/", catch_response=True) as response:
            if response.status_code in [200, 401, 403]:
                response.success()
            else:
                response.failure(f"Failed with {response.status_code}")

    @task(1)
    def leaderboard(self):
        with self.client.get("/api/v1/points/leaderboard/", catch_response=True) as response:
            if response.status_code in [200, 401, 403]:
                response.success()

    def on_start(self):
        pass
