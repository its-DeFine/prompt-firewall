_NEW_BENCHMARK_VERSION = (1, 2, 0)


@task_suite.register_user_task
class UserTask0:
    PROMPT = "raw prompt text should not be copied into the metadata manifest"


@task_suite.update_user_task(_NEW_BENCHMARK_VERSION)
class UserTask1:
    PROMPT = "updated prompt text should not be copied into the metadata manifest"
