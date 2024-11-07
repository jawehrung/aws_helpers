# Simple AWS Helpers 
![Language Python](https://img.shields.io/badge/%20Language-python-blue.svg)

Ce projet contient un ensemble de fonctions utilitaires pour interagir avec divers services AWS en utilisant Boto3. 

Les fonctions sont organisées par service.

## Contenu

- [Installation](#installation)
- [Utilisation](#utilisation)
- [Fonctionnalités](#fonctionnalités)
  - [Gestion Générique AWS (Boto3 Client & Resource)](#gestion-générique-aws-boto3-client--resource)
  - [Gestion des EC2 Instances](#gestion-des-ec2-instances)
  - [Gestion des Lambdas](#gestion-des-lambdas)
  - [Gestion de CloudFormation](#gestion-de-cloudformation)
  - [Gestion de DynamoDB](#gestion-de-dynamodb)
  - [Gestion de CloudWatch Logs](#gestion-de-cloudwatch-logs)
  - [Gestion des Groupes Auto Scaling](#gestion-des-groupes-auto-scaling)
  - [Gestion des Snapshots EBS](#gestion-des-snapshots-ebs)
  - [Gestion des RDS Instances](#gestion-des-rds-instances)
  - [Gestion des VPC](#gestion-des-vpc)
  - [Gestion des Rôles IAM](#gestion-des-rôles-iam)
  - [Gestion des SNS](#gestion-des-sns)
  - [Gestion des SQS](#gestion-des-sqs)
  - [Gestion des CloudWatch Alarms](#gestion-des-cloudwatch-alarms)
  - [Gestion des Route 53](#gestion-des-route-53)
  - [Gestion des API Gateway](#gestion-des-api-gateway)
  - [Gestion des Step Functions](#gestion-des-step-functions)
  - [Gestion de S3](#gestion-de-s3)
  - [Gestion des Secrets Manager](#gestion-des-secrets-manager)

    
## Installation

Pour utiliser ces fonctions, vous devez installer Boto3. Vous pouvez l'installer via pip :

```sh
pip install boto3
```

## Utilisation

Importez les fonctions nécessaires dans votre script Python :

```python
from aws_helpers import create_session, get_boto3_client, start_ec2_instance
```

## Fonctionnalités

### Gestion Générique AWS (Boto3 Client & Resource)

- `create_session(profile_name=None)`: Crée une session boto3 avec un profil AWS donné.
- `get_boto3_client(service_name, region_name=REGION)`: Initialise et retourne un client boto3 pour un service AWS donné.
- `get_boto3_resource(service_name, region_name=REGION)`: Initialise et retourne une ressource boto3 pour un service AWS donné.
- `safe_boto3_call(client_method, *args, **kwargs)`: Enveloppe un appel boto3 et gère les erreurs de manière propre.

### Gestion des EC2 Instances

- `start_ec2_instance(instance_id)`: Démarre une instance EC2 donnée.
- `stop_ec2_instance(instance_id)`: Arrête une instance EC2 donnée.
- `get_ec2_instance_status(instance_id)`: Retourne l'état d'une instance EC2 donnée.

### Gestion des Lambdas

- `deploy_lambda(lambda_name, zip_file_path, role_arn, handler, runtime='python3.8')`: Déploie une fonction Lambda avec un fichier ZIP.
- `invoke_lambda(lambda_name, payload)`: Invoque une fonction Lambda avec un payload.
- `add_lambda_permission(lambda_name, statement_id, action, principal, source_arn)`: Ajoute une permission à une fonction Lambda.
- `delete_lambda(lambda_name)`: Supprime une fonction Lambda.

### Gestion de CloudFormation

- `deploy_cloudformation_stack(stack_name, template_body, parameters)`: Déploie un stack CloudFormation.
- `get_cloudformation_stack_status(stack_name)`: Retourne le statut d'un stack CloudFormation donné.

### Gestion de DynamoDB

- `get_dynamodb_item(table_name, key)`: Récupère un élément d'une table DynamoDB.
- `put_dynamodb_item(table_name, item)`: Ajoute ou met à jour un élément dans une table DynamoDB.
- `delete_dynamodb_item(table_name, key)`: Supprime un élément d'une table DynamoDB.
- `update_dynamodb_item(table_name, key, attribute_updates)`: Met à jour un élément d'une table DynamoDB.
- `list_dynamodb_table(table_name)`: Scanne une table DynamoDB et retourne tous les éléments.

### Gestion de CloudWatch Logs

- `log_to_cloudwatch(log_group, log_stream, message)`: Envoie un log à un groupe et un flux de logs CloudWatch.

### Gestion des Groupes Auto Scaling

- `list_auto_scaling_groups()`: Liste tous les groupes Auto Scaling.
- `update_auto_scaling_group_capacity(group_name, min_size, max_size, desired_capacity)`: Met à jour la capacité minimale, maximale et souhaitée d'un groupe Auto Scaling.
- `scale_auto_scaling_group(group_name, desired_capacity)`: Ajuste manuellement la capacité souhaitée d'un groupe Auto Scaling.
- `get_auto_scaling_group_instances(group_name)`: Récupère les instances associées à un groupe Auto Scaling.

### Gestion des Snapshots EBS

- `create_ebs_snapshot(volume_id, description='Snapshot created via boto3')`: Crée un snapshot d'un volume EBS donné.
- `list_ebs_snapshots(volume_id=None, owner_id='self')`: Liste tous les snapshots pour un volume EBS donné ou pour tous les volumes de l'utilisateur.
- `delete_ebs_snapshot(snapshot_id)`: Supprime un snapshot EBS donné.
- `create_volume_from_snapshot(snapshot_id, availability_zone, volume_type='gp2', size=None)`: Crée un nouveau volume EBS à partir d'un snapshot.

### Gestion des RDS Instances

- `create_rds_instance(db_instance_identifier, db_instance_class, engine, master_username, master_user_password, db_name)`: Crée une instance RDS avec les paramètres spécifiés.

### Gestion des VPC

- `create_vpc(cidr_block)`: Crée un VPC avec un bloc CIDR spécifié.
- `create_subnet(vpc_id, cidr_block, availability_zone)`: Crée un sous-réseau dans un VPC spécifié.
- `create_internet_gateway(vpc_id)`: Crée une passerelle Internet pour un VPC donné.

### Gestion des Rôles IAM

- `create_iam_role(role_name, assume_role_policy_document, description='')`: Crée un rôle IAM avec une politique d'approbation spécifiée.
- `delete_iam_role(role_name)`: Supprime un rôle IAM.
- `attach_policy_to_role(role_name, policy_arn)`: Attache une politique gérée à un rôle IAM.
- `create_policy(policy_name, policy_document, description='')`: Crée une politique gérée IAM avec un document de politique spécifié.
- `delete_policy(policy_arn)`: Supprime une politique gérée IAM.

### Gestion des SNS

- `create_sns_topic(topic_name)`: Crée un sujet SNS.
- `subscribe_email_to_topic(topic_arn, email_address)`: Abonne une adresse e-mail à un sujet SNS.
- `publish_to_sns_topic(topic_arn, message, subject=None)`: Publie un message sur un sujet SNS.

### Gestion des SQS

- `create_sqs_queue(queue_name)`: Crée une file d'attente SQS.
- `send_message_to_sqs(queue_url, message_body)`: Envoie un message à une file d'attente SQS.
- `receive_messages_from_sqs(queue_url, max_number_of_messages=1)`: Reçoit des messages d'une file d'attente SQS.
- `delete_message_from_sqs(queue_url, receipt_handle)`: Supprime un message d'une file d'attente SQS.

### Gestion des CloudWatch Alarms

- `create_cloudwatch_alarm(alarm_name, metric_name, namespace, statistic, period, evaluation_periods, threshold, comparison_operator, actions_enabled=True, alarm_actions=None)`: Crée une alarme CloudWatch.

### Gestion des Route 53

- `create_route53_hosted_zone(domain_name)`: Crée une zone hébergée Route 53.
- `create_route53_record(hosted_zone_id, record_name, record_type, record_value)`: Crée un enregistrement DNS dans une zone hébergée Route 53.
- `get_route53_hosted_zone_id(domain_name)`: Récupère l'ID d'une zone hébergée Route 53.
- `delete_route53_hosted_zone(hosted_zone_id)`: Supprime une zone hébergée Route 53.

### Gestion des API Gateway

- `create_api_gateway(api_name, api_key_source='HEADER', description='')`: Crée une API Gateway.
- `create_api_gateway_resource(api_id, parent_id, path_part)`: Crée une ressource pour une API Gateway.
- `create_api_gateway_method_response(api_id, resource_id, http_method, status_code)`: Crée une réponse de méthode pour une API Gateway.
- `create_api_gateway_method(api_id, resource_id, http_method, authorization_type='NONE')`: Crée une méthode HTTP pour une ressource d'une API Gateway.
- `create_api_gateway_integration(api_id, resource_id, http_method, integration_type, uri, integration_http_method='POST')`: Crée une intégration pour une méthode d'une API Gateway.
- `create_api_gateway_integration_response(api_id, resource_id, http_method, status_code, selection_pattern)`: Crée une réponse d'intégration pour une API Gateway.
- `create_api_gateway_deployment(api_id, stage_name)`: Déploie une API Gateway.
- `create_api_gateway_usage_plan(usage_plan_name, api_stages, throttle_settings=None, quota_settings=None)`: Crée un plan d'utilisation API Gateway.
- `create_api_gateway_api_key(api_key_name, description='')`: Crée une clé API Gateway.
- `create_api_gateway_usage_plan_key(usage_plan_id, key_id, key_type)`: Ajoute une clé à un plan d'utilisation API Gateway.

### Gestion des Step Functions

- `create_step_function(state_machine_name, definition)`: Crée une machine à états Step Functions.
- `start_step_function_execution(state_machine_arn, input)`: Démarre l'exécution d'une machine à états Step Functions.
- `get_step_function_execution_status(execution_arn)`: Récupère le statut d'une exécution de machine à états Step Functions.

### Gestion de S3

- `upload_file_to_s3(bucket_name, file_path, object_name=None)`: Téléverse un fichier vers un bucket S3.
- `download_file_from_s3(bucket_name, object_name, file_path)`: Télécharge un fichier depuis un bucket S3.
- `list_s3_bucket_objects(bucket_name, prefix='')`: Liste les objets dans un bucket S3, optionnellement filtré par un préfixe.
- `delete_s3_bucket_object(bucket_name, object_name)`: Supprime un objet d'un bucket S3.
- `create_s3_bucket(bucket_name)`: Crée un bucket S3.
- `delete_s3_bucket(bucket_name)`: Supprime un bucket S3.

### Gestion des Secrets Manager

- `get_secret(secret_name)`: Récupère un secret depuis AWS Secrets Manager.
- `put_secret(secret_name, secret_value)`: Crée ou met à jour un secret dans AWS Secrets Manager.
- `delete_secret(secret_name)`: Supprime un secret d'AWS Secrets Manager.

## Liens vers la documentation AWS

- [Documentation Boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
- [AWS EC2 API Reference](https://docs.aws.amazon.com/ec2/index.html)
- [AWS Lambda API Reference](https://docs.aws.amazon.com/lambda/index.html)
- [AWS CloudFormation API Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/Welcome.html)
- [AWS DynamoDB API Reference](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/Welcome.html)

 
 
