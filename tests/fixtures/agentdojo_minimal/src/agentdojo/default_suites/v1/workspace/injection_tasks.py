@task_suite.register_injection_task
class InjectionTask0:
    GOAL = "raw injection goal should not be copied into the metadata manifest"

    def ground_truth(self, pre_environment):
        return [
            FunctionCall(
                function="send_email",
                args={"body": self.GOAL},
            )
        ]


@task_suite.update_injection_task((1, 2, 0), True)
class InjectionTask9:
    GOAL = "updated raw injection goal should not be copied into the metadata manifest"

    def ground_truth(self, pre_environment):
        return [
            FunctionCall(
                function="delete_file",
                args={"file_id": "file-1"},
            )
        ]
