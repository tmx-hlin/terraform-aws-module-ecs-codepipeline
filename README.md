
# terraform-aws-module-ecs-codepipeline

### How to use (Sameple)

Pipeline triggered anytime the `master` branch is updated.
```
module "ecs_push_pipeline" {
  source  = "terra.tmx.cloud/devops-tools/module-ecs-codepipeline/aws"
  version = "0.1.0"
  
  name               = "app"
  namespace          = "eg"
  stage              = "staging"
  github_oauth_token = "xxxxxxxxxxxxxx"
  repo_owner         = "cloudposse"
  repo_name          = "example"
  branch             = "master"
  service_name       = "example"
  ecs_cluster_name   = "example-ecs-cluster"
  privileged_mode    = "true"
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|:----:|:-----:|:-----:|
| attributes | Additional attributes (e.g. `policy` or `role`) | list | `<list>` | no |
| aws_account_id | AWS Account ID. Used as CodeBuild ENV variable when building Docker images. [For more info](http://docs.aws.amazon.com/codebuild/latest/userguide/sample-docker.html) | string | `` | no |
| aws_region | AWS Region, e.g. us-east-1. Used as CodeBuild ENV variable when building Docker images. [For more info](http://docs.aws.amazon.com/codebuild/latest/userguide/sample-docker.html) | string | `` | no |
| badge_enabled | Generates a publicly-accessible URL for the projects build badge. Available as badge_url attribute when enabled. | string | `false` | no |
| branch | Branch of the GitHub repository, _e.g._ `master` | string | - | yes |
| build_compute_type | `CodeBuild` instance size. Possible values are: `BUILD_GENERAL1_SMALL` `BUILD_GENERAL1_MEDIUM` `BUILD_GENERAL1_LARGE` | string | `BUILD_GENERAL1_SMALL` | no |
| build_image | Docker image for build environment, _e.g._ `aws/codebuild/docker:docker:17.09.0` | string | `aws/codebuild/docker:17.09.0` | no |
| build_timeout | How long in minutes, from 5 to 480 (8 hours), for AWS CodeBuild to wait until timing out any related build that does not get marked as completed. | string | `60` | no |
| buildspec | Declaration to use for building the project. [For more info](http://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html) | string | `` | no |
| delimiter | Delimiter to be used between `name`, `namespace`, `stage`, etc. | string | `-` | no |
| ecs_cluster_name | ECS Cluster Name | string | - | yes |
| enabled | Enable `CodePipeline` creation | string | `true` | no |
| environment_variables | A list of maps, that contain both the key 'name' and the key 'value' to be used as additional environment variables for the build. | list | `<list>` | no |
| github_oauth_token | GitHub Oauth Token with permissions to access private repositories | string | - | yes |
| github_webhook_events | A list of events which should trigger the webhook. See a list of [available events](https://developer.github.com/v3/activity/events/types/). | list | `<list>` | no |
| image_repo_name | ECR repository name to store the Docker image built by this module. Used as CodeBuild ENV variable when building Docker images. [For more info](http://docs.aws.amazon.com/codebuild/latest/userguide/sample-docker.html) | string | `UNSET` | no |
| image_tag | Docker image tag in the ECR repository, e.g. 'latest'. Used as CodeBuild ENV variable when building Docker images. [For more info](http://docs.aws.amazon.com/codebuild/latest/userguide/sample-docker.html) | string | `latest` | no |
| name | Solution name, e.g. 'app' or 'jenkins' | string | `app` | no |
| namespace | Namespace, which could be your organization name, e.g. 'cp' or 'cloudposse' | string | `global` | no |
| poll_source_changes | Periodically check the location of your source content and run the pipeline if changes are detected | string | `false` | no |
| privileged_mode | If set to true, enables running the Docker daemon inside a Docker container on the CodeBuild instance. Used when building Docker images | string | `false` | no |
| repo_name | GitHub repository name of the application to be built and deployed to ECS. | string | - | yes |
| repo_owner | GitHub Organization or Username. | string | - | yes |
| service_name | ECS Service Name | string | - | yes |
| stage | Stage, e.g. 'prod', 'staging', 'dev', or 'test' | string | `default` | no |
| tags | Additional tags (e.g. `map('BusinessUnit', 'XYZ')` | map | `<map>` | no |
| webhook_authentication | The type of authentication to use. One of IP, GITHUB_HMAC, or UNAUTHENTICATED. | string | `GITHUB_HMAC` | no |
| webhook_enabled | Set to false to prevent the module from creating any webhook resources | string | `true` | no |
| webhook_filter_json_path | The JSON path to filter on. | string | `$.ref` | no |
| webhook_filter_match_equals | The value to match on (e.g. refs/heads/{Branch}) | string | `refs/heads/{Branch}` | no |
| webhook_target_action | The name of the action in a pipeline you want to connect to the webhook. The action must be from the source (first) stage of the pipeline. | string | `Source` | no |

## Outputs

| Name | Description |
|------|-------------|
| badge_url | The URL of the build badge when badge_enabled is enabled |
| webhook_id | The CodePipeline webhook's ARN. |
| webhook_url | The CodePipeline webhook's URL. POST events to this endpoint to trigger the target. |


