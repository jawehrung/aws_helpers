# Simple Aws Helpers

import json
import boto3
import time


# ========================
# Constances
# ========================
REGION = 'eu-west-3'


# ========================
# Gestion Générique AWS (Boto3 Client & Resource)
# ========================
def create_session(profile_name=None):
    """Crée une session boto3 avec un profil AWS donné.

    Args:
        profile_name (str, optional): Le nom du profil AWS. Par défaut None.

    Returns:
        boto3.session: La session boto3 créée.
    """
    return boto3.Session(profile_name=profile_name)


def get_boto3_client(service_name, region_name=REGION):
    """Initialise et retourne un client boto3 pour un service AWS donné.

    Args:
        service_name (str): Le nom du service AWS.
        region_name (str, optional): La région AWS. Par défaut 'eu-west-3'.

    Returns:
        boto3.client: Le client boto3 initialisé.
    """
    return boto3.client(service_name, region_name=region_name)


def get_boto3_resource(service_name, region_name=REGION):
    """Initialise et retourne une ressource boto3 pour un service AWS donné.

    Args:
        service_name (str): Le nom du service AWS.
        region_name (str, optional): La région AWS. Par défaut 'eu-west-3'.

    Returns:
        boto3.resource: La ressource boto3 initialisée.
    """
    return boto3.resource(service_name, region_name=region_name)


def safe_boto3_call(client_method, *args, **kwargs):
    """Enveloppe un appel boto3 et gère les erreurs de manière propre.

    Args:
        client_method (method): La méthode du client boto3 à appeler.
        *args: Arguments positionnels pour la méthode.
        **kwargs: Arguments nommés pour la méthode.

    Returns:
        dict: La réponse de l'appel boto3 ou None en cas d'erreur.
    """
    try:
        return client_method(*args, **kwargs)
    except client_method.exceptions.ClientError as e:
        print(f"An error occurred: {e}")
        return None


# ========================
# Gestion des EC2 Instances
# ========================

def start_ec2_instance(instance_id):
    """Démarre une instance EC2 donnée.

    Args:
        instance_id (str): L'ID de l'instance EC2 à démarrer.
    """
    ec2_client = get_boto3_client('ec2')
    ec2_client.start_instances(InstanceIds=[instance_id])
    print(f"Starting instance: {instance_id}")


def stop_ec2_instance(instance_id):
    """Arrête une instance EC2 donnée.

    Args:
        instance_id (str): L'ID de l'instance EC2 à arrêter.
    """
    ec2_client = get_boto3_client('ec2')
    ec2_client.stop_instances(InstanceIds=[instance_id])
    print(f"Stopping instance: {instance_id}")


def get_ec2_instance_status(instance_id):
    """Retourne l'état d'une instance EC2 donnée.

    Args:
        instance_id (str): L'ID de l'instance EC2.

    Returns:
        dict: Le statut de l'instance EC2.
    """
    ec2_client = get_boto3_client('ec2')
    response = ec2_client.describe_instance_status(InstanceIds=[instance_id])
    return response['InstanceStatuses']


# ========================
# Gestion des Lambdas
# ========================
def deploy_lambda(lambda_name, zip_file_path, role_arn, handler, runtime='python3.8'):
    """Déploie une fonction Lambda avec un fichier ZIP.

    Args:
        lambda_name (str): Le nom de la fonction Lambda.
        zip_file_path (str): Le chemin du fichier ZIP contenant le code de la Lambda.
        role_arn (str): L'ARN du rôle IAM pour la Lambda.
        handler (str): Le handler de la Lambda.
        runtime (str, optional): Le runtime de la Lambda. Par défaut 'python3.8'.
    """
    lambda_client = get_boto3_client('lambda')
    with open(zip_file_path, 'rb') as f:
        zip_content = f.read()

    lambda_client.create_function(
        FunctionName=lambda_name,
        Runtime=runtime,
        Role=role_arn,
        Handler=handler,
        Code={'ZipFile': zip_content},
        Publish=True
    )
    print(f"Lambda {lambda_name} deployed")


def invoke_lambda(lambda_name, payload):
    """Invoque une fonction Lambda avec un payload.

    Args:
        lambda_name (str): Le nom de la fonction Lambda.
        payload (str): Le payload à envoyer à la Lambda.

    Returns:
        str: La réponse de la fonction Lambda.
    """
    lambda_client = get_boto3_client('lambda')
    response = lambda_client.invoke(
        FunctionName=lambda_name,
        Payload=payload,
    )
    return response['Payload'].read().decode('utf-8')


def add_lambda_permission(lambda_name, statement_id, action, principal, source_arn):
    """Ajoute une permission à une fonction Lambda.

    Args:
        lambda_name (str): Le nom de la fonction Lambda.
        statement_id (str): L'ID de la déclaration.
        action (str): L'action à autoriser.
        principal (str): Le principal à autoriser.
        source_arn (str): L'ARN source.
    """
    lambda_client = get_boto3_client('lambda')
    lambda_client.add_permission(
        FunctionName=lambda_name,
        StatementId=statement_id,
        Action=action,
        Principal=principal,
        SourceArn=source_arn
    )
    print(f"Permission added to Lambda {lambda_name}")


def delete_lambda(lambda_name):
    """Supprime une fonction Lambda.

    Args:
        lambda_name (str): Le nom de la fonction Lambda à supprimer.
    """
    lambda_client = get_boto3_client('lambda')
    lambda_client.delete_function(FunctionName=lambda_name)
    print(f"Lambda {lambda_name} deleted")


# ========================
# Gestion de CloudFormation
# ========================

def deploy_cloudformation_stack(stack_name, template_body, parameters):
    """Déploie un stack CloudFormation.

    Args:
        stack_name (str): Le nom du stack CloudFormation.
        template_body (str): Le corps du template CloudFormation.
        parameters (list): La liste des paramètres pour le stack.
    """
    cf_client = get_boto3_client('cloudformation')
    cf_client.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=parameters,
        Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM']
    )
    print(f"CloudFormation stack {stack_name} creation initiated.")


def get_cloudformation_stack_status(stack_name):
    """Retourne le statut d'un stack CloudFormation donné.

    Args:
        stack_name (str): Le nom du stack CloudFormation.

    Returns:
        str: Le statut du stack CloudFormation.
    """
    cf_client = get_boto3_client('cloudformation')
    response = cf_client.describe_stacks(StackName=stack_name)
    return response['Stacks'][0]['StackStatus']


# ========================
# Gestion de DynamoDB
# ========================
def get_dynamodb_item(table_name, key):
    """Récupère un élément d'une table DynamoDB.

    Args:
        table_name (str): Le nom de la table DynamoDB.
        key (dict): La clé de l'élément à récupérer.

    Returns:
        dict: L'élément récupéré ou None si non trouvé.
    """
    dynamo_client = get_boto3_client('dynamodb')
    response = dynamo_client.get_item(TableName=table_name, Key=key)
    return response.get('Item', None)


def put_dynamodb_item(table_name, item):
    """Ajoute ou met à jour un élément dans une table DynamoDB.

    Args:
        table_name (str): Le nom de la table DynamoDB.
        item (dict): L'élément à ajouter ou mettre à jour.
    """
    dynamo_client = get_boto3_client('dynamodb')
    dynamo_client.put_item(TableName=table_name, Item=item)
    print(f"Item added to {table_name}")


def delete_dynamodb_item(table_name, key):
    """Supprime un élément d'une table DynamoDB.

    Args:
        table_name (str): Le nom de la table DynamoDB.
        key (dict): La clé de l'élément à supprimer.
    """
    dynamo_client = get_boto3_client('dynamodb')
    dynamo_client.delete_item(TableName=table_name, Key=key)
    print(f"Item deleted from {table_name}")


def update_dynamodb_item(table_name, key, attribute_updates):
    """Met à jour un élément d'une table DynamoDB.

    Args:
        table_name (str): Le nom de la table DynamoDB.
        key (dict): La clé de l'élément à mettre à jour.
        attribute_updates (dict): Les attributs à mettre à jour.
    """
    dynamo_client = get_boto3_client('dynamodb')
    dynamo_client.update_item(
        TableName=table_name,
        Key=key,
        AttributeUpdates=attribute_updates
    )
    print(f"Item updated in {table_name}")


def list_dynamodb_table(table_name):
    """Scanne une table DynamoDB et retourne tous les éléments.

    Args:
        table_name (str): Le nom de la table DynamoDB à scanner.

    Returns:
        list: La liste des éléments scannés.
    """
    dynamo_resource = get_boto3_resource('dynamodb')
    table = dynamo_resource.Table(table_name)
    response = table.scan()
    return response['Items']


def query_dynamodb_table(table_name, key_condition_expression, expression_attribute_values):
    """Interroge une table DynamoDB et retourne les éléments correspondants.

    Args:
        table_name (str): Le nom de la table DynamoDB à interroger.
        key_condition_expression (str): L'expression de condition de clé.
        expression_attribute_values (dict): Les valeurs d'attribut d'expression.

    Returns:
        list: La liste des éléments correspondants à la requête.
    """
    dynamo_client = get_boto3_client('dynamodb')
    response = dynamo_client.query(
        TableName=table_name,
        KeyConditionExpression=key_condition_expression,
        ExpressionAttributeValues=expression_attribute_values
    )
    return response['Items']


def create_dynamodb_table(table_name, key_schema, attribute_definitions, provisioned_throughput):
    """Crée une table DynamoDB avec les paramètres spécifiés.

    Args:
        table_name (str): Le nom de la table DynamoDB.
        key_schema (list): Le schéma de clé de la table.
        attribute_definitions (list): Les définitions d'attribut de la table.
        provisioned_throughput (dict): Le débit provisionné pour la table.
    """
    dynamo_client = get_boto3_client('dynamodb')
    dynamo_client.create_table(
        TableName=table_name,
        KeySchema=key_schema,
        AttributeDefinitions=attribute_definitions,
        ProvisionedThroughput=provisioned_throughput
    )
    print(f"DynamoDB table {table_name} created")


def delete_dynamodb_table(table_name):
    """Supprime une table DynamoDB.

    Args:
        table_name (str): Le nom de la table DynamoDB à supprimer.
    """
    dynamo_client = get_boto3_client('dynamodb')
    dynamo_client.delete_table(TableName=table_name)
    print(f"DynamoDB table {table_name} deleted")


# ========================
# Gestion de CloudWatch Logs
# ========================
def log_to_cloudwatch(log_group, log_stream, message):
    """Envoie un log à un groupe et un flux de logs CloudWatch.

    Args:
        log_group (str): Le nom du groupe de logs CloudWatch.
        log_stream (str): Le nom du flux de logs CloudWatch.
        message (str): Le message de log à envoyer.
    """
    cw_client = get_boto3_client('logs')
    cw_client.put_log_events(
        logGroupName=log_group,
        logStreamName=log_stream,
        logEvents=[{
            'timestamp': int(time.time() * 1000),
            'message': message
        }]
    )


# ========================
# Gestion des Groupes Auto Scaling
# ========================
def list_auto_scaling_groups():
    """Liste tous les groupes Auto Scaling.

    Returns:
        list: La liste des groupes Auto Scaling.
    """
    asg_client = get_boto3_client('autoscaling')
    response = asg_client.describe_auto_scaling_groups()
    return response['AutoScalingGroups']


def update_auto_scaling_group_capacity(group_name, min_size, max_size, desired_capacity):
    """Met à jour la capacité minimale, maximale et souhaitée d'un groupe Auto Scaling.

    Args:
        group_name (str): Le nom du groupe Auto Scaling.
        min_size (int): La capacité minimale.
        max_size (int): La capacité maximale.
        desired_capacity (int): La capacité souhaitée.
    """
    asg_client = get_boto3_client('autoscaling')
    asg_client.update_auto_scaling_group(
        AutoScalingGroupName=group_name,
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired_capacity
    )
    print(f"Updated capacity for Auto Scaling group {group_name}")


def scale_auto_scaling_group(group_name, desired_capacity):
    """Ajuste manuellement la capacité souhaitée d'un groupe Auto Scaling.

    Args:
        group_name (str): Le nom du groupe Auto Scaling.
        desired_capacity (int): La capacité souhaitée.
    """
    asg_client = get_boto3_client('autoscaling')
    asg_client.set_desired_capacity(
        AutoScalingGroupName=group_name,
        DesiredCapacity=desired_capacity,
        HonorCooldown=False  # Forcer le scaling immédiatement sans cooldown
    )
    print(f"Scaling Auto Scaling group {group_name} to {desired_capacity} instances")


def get_auto_scaling_group_instances(group_name):
    """Récupère les instances associées à un groupe Auto Scaling.

    Args:
        group_name (str): Le nom du groupe Auto Scaling.

    Returns:
        list: La liste des instances associées au groupe Auto Scaling.
    """
    asg_client = get_boto3_client('autoscaling')
    response = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])
    if response['AutoScalingGroups']:
        instances = response['AutoScalingGroups'][0]['Instances']
        return instances
    return []


# ========================
# Gestion des Snapshots EBS
# ========================
def create_ebs_snapshot(volume_id, description='Snapshot created via boto3'):
    """Crée un snapshot d'un volume EBS donné.

    Args:
        volume_id (str): L'ID du volume EBS.
        description (str, optional): La description du snapshot. Par défaut 'Snapshot created via boto3'.

    Returns:
        str: L'ID du snapshot créé.
    """
    ec2_client = get_boto3_client('ec2')
    response = ec2_client.create_snapshot(
        VolumeId=volume_id,
        Description=description
    )
    snapshot_id = response['SnapshotId']
    print(f"Snapshot {snapshot_id} created for volume {volume_id}")
    return snapshot_id


def list_ebs_snapshots(volume_id=None, owner_id='self'):
    """Liste tous les snapshots pour un volume EBS donné ou pour tous les volumes de l'utilisateur.

    Args:
        volume_id (str, optional): L'ID du volume EBS. Par défaut None.
        owner_id (str, optional): L'ID du propriétaire des snapshots. Par défaut 'self'.

    Returns:
        list: La liste des snapshots.
    """
    ec2_client = get_boto3_client('ec2')
    filters = []
    if volume_id:
        filters.append({'Name': 'volume-id', 'Values': [volume_id]})

    response = ec2_client.describe_snapshots(OwnerIds=[owner_id], Filters=filters)
    return response['Snapshots']


def delete_ebs_snapshot(snapshot_id):
    """Supprime un snapshot EBS donné.

    Args:
        snapshot_id (str): L'ID du snapshot à supprimer.
    """
    ec2_client = get_boto3_client('ec2')
    ec2_client.delete_snapshot(SnapshotId=snapshot_id)
    print(f"Snapshot {snapshot_id} deleted")


def create_volume_from_snapshot(snapshot_id, availability_zone, volume_type='gp2', size=None):
    """Crée un nouveau volume EBS à partir d'un snapshot.

    Args:
        snapshot_id (str): L'ID du snapshot.
        availability_zone (str): La zone de disponibilité.
        volume_type (str, optional): Le type de volume. Par défaut 'gp2'.
        size (int, optional): La taille du volume en GiB. Par défaut None.

    Returns:
        str: L'ID du volume créé.
    """
    ec2_client = get_boto3_client('ec2')
    params = {
        'SnapshotId': snapshot_id,
        'AvailabilityZone': availability_zone,
        'VolumeType': volume_type
    }
    if size:
        params['Size'] = size  # Si la taille du volume doit être supérieure à celle du snapshot original

    response = ec2_client.create_volume(**params)
    volume_id = response['VolumeId']
    print(f"Volume {volume_id} created from snapshot {snapshot_id}")
    return volume_id


# ========================
# Gestion des RDS Instances
# ========================
def create_rds_instance(db_instance_identifier, db_instance_class, engine, master_username, master_user_password, db_name):
    """Crée une instance RDS avec les paramètres spécifiés.

    Args:
        db_instance_identifier (str): L'identifiant de l'instance RDS.
        db_instance_class (str): La classe de l'instance RDS.
        engine (str): Le moteur de base de données.
        master_username (str): Le nom d'utilisateur maître.
        master_user_password (str): Le mot de passe de l'utilisateur maître.
        db_name (str): Le nom de la base de données.

    Returns:
        str: L'ID de l'instance RDS créée.
    """
    rds_client = get_boto3_client('rds')
    response = rds_client.create_db_instance(
        DBInstanceIdentifier=db_instance_identifier,
        DBInstanceClass=db_instance_class,
        Engine=engine,
        MasterUsername=master_username,
        MasterUserPassword=master_user_password,
        DBName=db_name,
        AllocatedStorage=20  # Taille de stockage par défaut
    )
    return response['DBInstance']['DBInstanceIdentifier']


# ========================
# Gestion des VPC
# ========================
def create_vpc(cidr_block):
    """Crée un VPC avec un bloc CIDR spécifié.

    Args:
        cidr_block (str): Le bloc CIDR pour le VPC.

    Returns:
        str: L'ID du VPC créé.
    """
    ec2_client = get_boto3_client('ec2')
    response = ec2_client.create_vpc(CidrBlock=cidr_block)
    vpc_id = response['Vpc']['VpcId']
    print(f"VPC {vpc_id} created with CIDR block {cidr_block}")
    return vpc_id

def create_subnet(vpc_id, cidr_block, availability_zone):
    """Crée un sous-réseau dans un VPC spécifié.

    Args:
        vpc_id (str): L'ID du VPC.
        cidr_block (str): Le bloc CIDR pour le sous-réseau.
        availability_zone (str): La zone de disponibilité.

    Returns:
        str: L'ID du sous-réseau créé.
    """
    ec2_client = get_boto3_client('ec2')
    response = ec2_client.create_subnet(
        VpcId=vpc_id,
        CidrBlock=cidr_block,
        AvailabilityZone=availability_zone
    )
    subnet_id = response['Subnet']['SubnetId']
    print(f"Subnet {subnet_id} created in VPC {vpc_id} with CIDR block {cidr_block}")
    return subnet_id


def create_internet_gateway(vpc_id):
    """Crée une passerelle Internet pour un VPC donné.

    Args:
        vpc_id (str): L'ID du VPC.

    Returns:
        str: L'ID de la passerelle Internet créée.
    """
    ec2_client = get_boto3_client('ec2')
    response = ec2_client.create_internet_gateway()
    gateway_id = response['InternetGateway']['InternetGatewayId']
    ec2_client.attach_internet_gateway(InternetGatewayId=gateway_id, VpcId=vpc_id)
    print(f"Internet Gateway {gateway_id} attached to VPC {vpc_id}")
    return gateway_id



# ========================
# Gestion des Rôles IAM
# ========================
def create_iam_role(role_name, assume_role_policy_document, description=''):
    """Crée un rôle IAM avec une politique d'approbation spécifiée.

    Args:
        role_name (str): Le nom du rôle IAM.
        assume_role_policy_document (str): La politique d'approbation en format JSON.
        description (str, optional): La description du rôle. Par défaut ''.

    Returns:
        str: L'ARN du rôle IAM créé.
    """
    iam_client = get_boto3_client('iam')
    response = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=assume_role_policy_document,
        Description=description
    )
    return response['Role']['Arn']

def delete_iam_role(role_name):
    """Supprime un rôle IAM.

    Args:
        role_name (str): Le nom du rôle IAM à supprimer.
    """
    iam_client = get_boto3_client('iam')
    iam_client.delete_role(RoleName=role_name)
    print(f"IAM role {role_name} deleted")


def attach_policy_to_role(role_name, policy_arn):
    """Attache une politique gérée à un rôle IAM.

    Args:
        role_name (str): Le nom du rôle IAM.
        policy_arn (str): L'ARN de la politique à attacher.
    """
    iam_client = get_boto3_client('iam')
    iam_client.attach_role_policy(
        RoleName=role_name,
        PolicyArn=policy_arn
    )
    print(f"Policy {policy_arn} attached to role {role_name}")


def create_policy(policy_name, policy_document, description=''):
    """Crée une politique gérée IAM avec un document de politique spécifié.

    Args:
        policy_name (str): Le nom de la politique gérée.
        policy_document (str): Le document de politique en format JSON.
        description (str, optional): La description de la politique. Par défaut ''.

    Returns:
        str: L'ARN de la politique gérée créée.
    """
    iam_client = get_boto3_client('iam')
    response = iam_client.create_policy(
        PolicyName=policy_name,
        PolicyDocument=policy_document,
        Description=description
    )
    return response['Policy']['Arn']


def delete_policy(policy_arn):
    """Supprime une politique gérée IAM.

    Args:
        policy_arn (str): L'ARN de la politique gérée à supprimer.
    """
    iam_client = get_boto3_client('iam')
    iam_client.delete_policy(PolicyArn=policy_arn)
    print(f"Policy {policy_arn} deleted")


# ========================
# Gestion des SNS (Simple Notification Service)
# ========================
def create_sns_topic(topic_name):
    """Crée un sujet SNS.

    Args:
        topic_name (str): Le nom du sujet SNS.

    Returns:
        str: L'ARN du sujet SNS créé.
    """
    sns_client = get_boto3_client('sns')
    response = sns_client.create_topic(Name=topic_name)
    return response['TopicArn']


def subscribe_email_to_topic(topic_arn, email_address):
    """Abonne une adresse e-mail à un sujet SNS.

    Args:
        topic_arn (str): L'ARN du sujet SNS.
        email_address (str): L'adresse e-mail à abonner.
    """
    sns_client = get_boto3_client('sns')
    sns_client.subscribe(
        TopicArn=topic_arn,
        Protocol='email',
        Endpoint=email_address
    )
    print(f"Subscribed {email_address} to SNS topic {topic_arn}")


def publish_to_sns_topic(topic_arn, message, subject=None):
    """Publie un message sur un sujet SNS.

    Args:
        topic_arn (str): L'ARN du sujet SNS.
        message (str): Le message à publier.
        subject (str, optional): Le sujet du message. Par défaut None.
    """
    sns_client = get_boto3_client('sns')
    sns_client.publish(
        TopicArn=topic_arn,
        Message=message,
        Subject=subject
    )
    print(f"Message published to {topic_arn}")


# ========================
# Gestion des SQS (Simple Queue Service)
# ========================
def create_sqs_queue(queue_name):
    """Crée une file d'attente SQS.

    Args:
        queue_name (str): Le nom de la file d'attente SQS.

    Returns:
        str: L'URL de la file d'attente SQS créée.
    """
    sqs_client = get_boto3_client('sqs')
    response = sqs_client.create_queue(QueueName=queue_name)
    return response['QueueUrl']

def send_message_to_sqs(queue_url, message_body):
    """Envoie un message à une file d'attente SQS.

    Args:
        queue_url (str): L'URL de la file d'attente SQS.
        message_body (str): Le corps du message à envoyer.
    """
    sqs_client = get_boto3_client('sqs')
    sqs_client.send_message(
        QueueUrl=queue_url,
        MessageBody=message_body
    )
    print(f"Message sent to queue {queue_url}")

def receive_messages_from_sqs(queue_url, max_number_of_messages=1):
    """Reçoit des messages d'une file d'attente SQS.

    Args:
        queue_url (str): L'URL de la file d'attente SQS.
        max_number_of_messages (int, optional): Le nombre maximal de messages à recevoir. Par défaut 1.

    Returns:
        list: La liste des messages reçus.
    """
    sqs_client = get_boto3_client('sqs')
    response = sqs_client.receive_message(
        QueueUrl=queue_url,
        MaxNumberOfMessages=max_number_of_messages
    )
    return response.get('Messages', [])

def delete_message_from_sqs(queue_url, receipt_handle):
    """Supprime un message d'une file d'attente SQS.

    Args:
        queue_url (str): L'URL de la file d'attente SQS.
        receipt_handle (str): Le handle de réception du message.
    """
    sqs_client = get_boto3_client('sqs')
    sqs_client.delete_message(
        QueueUrl=queue_url,
        ReceiptHandle=receipt_handle
    )
    print(f"Message deleted from queue {queue_url}")


# ========================
# Gestion des CloudWatch Alarms
# ========================
def create_cloudwatch_alarm(alarm_name, metric_name, namespace, statistic, period, evaluation_periods, threshold, comparison_operator, actions_enabled=True, alarm_actions=None):
    """Crée une alarme CloudWatch.

    Args:
        alarm_name (str): Le nom de l'alarme.
        metric_name (str): Le nom de la métrique.
        namespace (str): Le namespace de la métrique.
        statistic (str): La statistique de la métrique.
        period (int): La période de la métrique en secondes.
        evaluation_periods (int): Le nombre de périodes d'évaluation.
        threshold (float): Le seuil de l'alarme.
        comparison_operator (str): L'opérateur de comparaison.
        actions_enabled (bool, optional): Si les actions sont activées. Par défaut True.
        alarm_actions (list, optional): La liste des actions d'alarme. Par défaut None.
    """
    cw_client = get_boto3_client('cloudwatch')
    cw_client.put_metric_alarm(
        AlarmName=alarm_name,
        MetricName=metric_name,
        Namespace=namespace,
        Statistic=statistic,
        Period=period,
        EvaluationPeriods=evaluation_periods,
        Threshold=threshold,
        ComparisonOperator=comparison_operator,
        ActionsEnabled=actions_enabled,
        AlarmActions=alarm_actions or []
    )
    print(f"CloudWatch alarm {alarm_name} created")


# ========================
# Gestion des Route 53
# ========================
def create_route53_hosted_zone(domain_name):
    """Crée une zone hébergée Route 53.

    Args:
        domain_name (str): Le nom de domaine de la zone hébergée.

    Returns:
        str: L'ID de la zone hébergée créée.
    """
    route53_client = get_boto3_client('route53')
    response = route53_client.create_hosted_zone(Name=domain_name)
    return response['HostedZone']['Id']

def create_route53_record(hosted_zone_id, record_name, record_type, record_value):
    """Crée un enregistrement DNS dans une zone hébergée Route 53.

    Args:
        hosted_zone_id (str): L'ID de la zone hébergée.
        record_name (str): Le nom de l'enregistrement.
        record_type (str): Le type de l'enregistrement.
        record_value (str): La valeur de l'enregistrement.
    """
    route53_client = get_boto3_client('route53')
    route53_client.change_resource_record_sets(
        HostedZoneId=hosted_zone_id,
        ChangeBatch={
            'Changes': [{
                'Action': 'UPSERT',
                'ResourceRecordSet': {
                    'Name': record_name,
                    'Type': record_type,
                    'TTL': 300,
                    'ResourceRecords': [{'Value': record_value}]
                }
            }]
        }
    )
    print(f"Route 53 record {record_name} created in hosted zone {hosted_zone_id}")

def get_route53_hosted_zone_id(domain_name):
    """Récupère l'ID d'une zone hébergée Route 53.

    Args:
        domain_name (str): Le nom de domaine de la zone hébergée.

    Returns:
        str: L'ID de la zone hébergée.
    """
    route53_client = get_boto3_client('route53')
    response = route53_client.list_hosted_zones_by_name(DNSName=domain_name)
    return response['HostedZones'][0]['Id']


def delete_route53_hosted_zone(hosted_zone_id):
    """Supprime une zone hébergée Route 53.

    Args:
        hosted_zone_id (str): L'ID de la zone hébergée à supprimer.
    """
    route53_client = get_boto3_client('route53')
    route53_client.delete_hosted_zone(Id=hosted_zone_id)
    print(f"Route 53 hosted zone {hosted_zone_id} deleted")


# ========================
# Gestion des API Gateway
# ========================
def create_api_gateway(api_name, api_key_source='HEADER', description=''):
    """Crée une API Gateway.

    Args:
        api_name (str): Le nom de l'API Gateway.
        api_key_source (str, optional): La source de la clé API. Par défaut 'HEADER'.
        description (str, optional): La description de l'API Gateway. Par défaut ''.

    Returns:
        str: L'ID de l'API Gateway créée.
    """
    apigateway_client = get_boto3_client('apigateway')
    response = apigateway_client.create_rest_api(
        name=api_name,
        apiKeySource=api_key_source,
        description=description
    )
    return response['id']


def create_api_gateway_resource(api_id, parent_id, path_part):
    """Crée une ressource pour une API Gateway.

    Args:
        api_id (str): L'ID de l'API Gateway.
        parent_id (str): L'ID de la ressource parente.
        path_part (str): Le chemin de la ressource.

    Returns:
        str: L'ID de la ressource créée.
    """
    apigateway_client = get_boto3_client('apigateway')
    response = apigateway_client.create_resource(
        restApiId=api_id,
        parentId=parent_id,
        pathPart=path_part
    )
    return response['id']


def create_api_gateway_method_response(api_id, resource_id, http_method, status_code):
    """Crée une réponse de méthode pour une API Gateway.

    Args:
        api_id (str): L'ID de l'API Gateway.
        resource_id (str): L'ID de la ressource.
        http_method (str): La méthode HTTP.
        status_code (str): Le code de statut HTTP.

    Returns:
        str: L'ID de la réponse de méthode créée.
    """
    apigateway_client = get_boto3_client('apigateway')
    response = apigateway_client.put_method_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod=http_method,
        statusCode=status_code
    )
    return response['id']


def create_api_gateway_method(api_id, resource_id, http_method, authorization_type='NONE'):
    """Crée une méthode HTTP pour une ressource d'une API Gateway.

    Args:
        api_id (str): L'ID de l'API Gateway.
        resource_id (str): L'ID de la ressource.
        http_method (str): La méthode HTTP.
        authorization_type (str, optional): Le type d'autorisation. Par défaut 'NONE'.

    Returns:
        str: L'ID de la méthode créée.
    """
    apigateway_client = get_boto3_client('apigateway')
    response = apigateway_client.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod=http_method,
        authorizationType=authorization_type
    )
    return response['id']


def create_api_gateway_integration(api_id, resource_id, http_method, integration_type, uri, integration_http_method='POST'):
    """Crée une intégration pour une méthode d'une API Gateway.

    Args:
        api_id (str): L'ID de l'API Gateway.
        resource_id (str): L'ID de la ressource.
        http_method (str): La méthode HTTP.
        integration_type (str): Le type d'intégration.
        uri (str): L'URI de l'intégration.
        integration_http_method (str, optional): La méthode HTTP de l'intégration. Par défaut 'POST'.

    Returns:
        str: L'ID de l'intégration créée.
    """
    apigateway_client = get_boto3_client('apigateway')
    response = apigateway_client.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod=http_method,
        type=integration_type,
        uri=uri,
        integrationHttpMethod=integration_http_method
    )
    return response['id']


def create_api_gateway_integration_response(api_id, resource_id, http_method, status_code, selection_pattern):
    """Crée une réponse d'intégration pour une API Gateway.

    Args:
        api_id (str): L'ID de l'API Gateway.
        resource_id (str): L'ID de la ressource.
        http_method (str): La méthode HTTP.
        status_code (str): Le code de statut HTTP.
        selection_pattern (str): Le pattern de sélection.

    Returns:
        str: L'ID de la réponse d'intégration créée.
    """
    apigateway_client = get_boto3_client('apigateway')
    response = apigateway_client.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod=http_method,
        statusCode=status_code,
        selectionPattern=selection_pattern
    )
    return response['id']


def create_api_gateway_deployment(api_id, stage_name):
    """Déploie une API Gateway.

    Args:
        api_id (str): L'ID de l'API Gateway.
        stage_name (str): Le nom du stage.

    Returns:
        str: L'ID du déploiement créé.
    """
    apigateway_client = get_boto3_client('apigateway')
    response = apigateway_client.create_deployment(
        restApiId=api_id,
        stageName=stage_name
    )
    return response['id']


def create_api_gateway_usage_plan(usage_plan_name, api_stages, throttle_settings=None, quota_settings=None):
    """Crée un plan d'utilisation API Gateway.

    Args:
        usage_plan_name (str): Le nom du plan d'utilisation.
        api_stages (list): La liste des stages de l'API.
        throttle_settings (dict, optional): Les paramètres de limitation. Par défaut None.
        quota_settings (dict, optional): Les paramètres de quota. Par défaut None.

    Returns:
        str: L'ID du plan d'utilisation créé.
    """
    apigateway_client = get_boto3_client('apigateway')
    response = apigateway_client.create_usage_plan(
        name=usage_plan_name,
        apiStages=api_stages,
        throttle=throttle_settings or {},
        quota=quota_settings or {}
    )
    return response['id']


def create_api_gateway_api_key(api_key_name, description=''):
    """Crée une clé API Gateway.

    Args:
        api_key_name (str): Le nom de la clé API.
        description (str, optional): La description de la clé API. Par défaut ''.

    Returns:
        str: L'ID de la clé API créée.
    """
    apigateway_client = get_boto3_client('apigateway')
    response = apigateway_client.create_api_key(
        name=api_key_name,
        description=description
    )
    return response['id']


def create_api_gateway_usage_plan_key(usage_plan_id, key_id, key_type):
    """Ajoute une clé à un plan d'utilisation API Gateway.

    Args:
        usage_plan_id (str): L'ID du plan d'utilisation.
        key_id (str): L'ID de la clé.
        key_type (str): Le type de clé.
    """
    apigateway_client = get_boto3_client('apigateway')
    apigateway_client.create_usage_plan_key(
        usagePlanId=usage_plan_id,
        keyId=key_id,
        keyType=key_type
    )
    print(f"API key {key_id} added to usage plan {usage_plan_id}")


# ========================
# Gestion des Step Functions
# ========================
def create_step_function(state_machine_name, definition):
    """Crée une machine à états Step Functions.

    Args:
        state_machine_name (str): Le nom de la machine à états.
        definition (dict): La définition de la machine à états.

    Returns:
        str: L'ARN de la machine à états créée.
    """
    stepfunctions_client = get_boto3_client('stepfunctions')
    response = stepfunctions_client.create_state_machine(
        name=state_machine_name,
        definition=json.dumps(definition),
        roleArn='arn:aws:iam::123456789012:role/service-role/StatesExecutionRole-us-east-1'
    )
    return response['stateMachineArn']


def start_step_function_execution(state_machine_arn, input):
    """Démarre l'exécution d'une machine à états Step Functions.

    Args:
        state_machine_arn (str): L'ARN de la machine à états.
        input (dict): L'entrée de la machine à états.

    Returns:
        str: L'ARN de l'exécution de la machine à états.
    """
    stepfunctions_client = get_boto3_client('stepfunctions')
    response = stepfunctions_client.start_execution(
        stateMachineArn=state_machine_arn,
        input=json.dumps(input)
    )
    return response['executionArn']


def get_step_function_execution_status(execution_arn):
    """Récupère le statut d'une exécution de machine à états Step Functions.

    Args:
        execution_arn (str): L'ARN de l'exécution.

    Returns:
        str: Le statut de l'exécution.
    """
    stepfunctions_client = get_boto3_client('stepfunctions')
    response = stepfunctions_client.describe_execution(
        executionArn=execution_arn
    )
    return response['status']


# ========================
# Gestion de S3
# ========================
def upload_file_to_s3(bucket_name, file_path, object_name=None):
    """Téléverse un fichier vers un bucket S3.

    Args:
        bucket_name (str): Le nom du bucket S3.
        file_path (str): Le chemin du fichier à téléverser.
        object_name (str, optional): Le nom de l'objet dans S3. Par défaut, utilise le file_path.
    """
    s3_client = get_boto3_client('s3')
    object_name = object_name or file_path
    s3_client.upload_file(file_path, bucket_name, object_name)


def download_file_from_s3(bucket_name, object_name, file_path):
    """Télécharge un fichier depuis un bucket S3.

    Args:
        bucket_name (str): Le nom du bucket S3.
        object_name (str): Le nom de l'objet dans S3.
        file_path (str): Le chemin où le fichier sera téléchargé.
    """
    s3_client = get_boto3_client('s3')
    s3_client.download_file(bucket_name, object_name, file_path)


def list_s3_bucket_objects(bucket_name, prefix=''):
    """Liste les objets dans un bucket S3, optionnellement filtré par un préfixe.

    Args:
        bucket_name (str): Le nom du bucket S3.
        prefix (str, optional): Le préfixe pour filtrer les objets. Par défaut, ''.

    Returns:
        list: La liste des clés des objets dans le bucket.
    """
    s3_client = get_boto3_client('s3')
    response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
    return [content['Key'] for content in response.get('Contents', [])]


def delete_s3_bucket_object(bucket_name, object_name):
    """Supprime un objet d'un bucket S3.

    Args:
        bucket_name (str): Le nom du bucket S3.
        object_name (str): Le nom de l'objet à supprimer.
    """
    s3_client = get_boto3_client('s3')
    s3_client.delete_object(Bucket=bucket_name, Key=object_name)
    print(f"Object {object_name} deleted from bucket {bucket_name}")


def create_s3_bucket(bucket_name):
    """Crée un bucket S3.

    Args:
        bucket_name (str): Le nom du bucket S3.

    Returns:
        str: Le nom du bucket S3 créé.
    """
    s3_client = get_boto3_client('s3')
    s3_client.create_bucket(Bucket=bucket_name)
    print(f"S3 bucket {bucket_name} created")
    return bucket_name


def delete_s3_bucket(bucket_name):
    """Supprime un bucket S3.

    Args:
        bucket_name (str): Le nom du bucket S3.
    """
    s3_client = get_boto3_client('s3')
    s3_client.delete_bucket(Bucket=bucket_name)
    print(f"S3 bucket {bucket_name} deleted")


# ========================
# Gestion des Secrets Manager
# ========================
def get_secret(secret_name):
    """Récupère un secret depuis AWS Secrets Manager.

    Args:
        secret_name (str): Le nom du secret à récupérer.

    Returns:
        str: La valeur du secret.
    """
    secrets_client = get_boto3_client('secretsmanager')
    response = secrets_client.get_secret_value(SecretId=secret_name)
    return response['SecretString']


def put_secret(secret_name, secret_value):
    """Crée ou met à jour un secret dans AWS Secrets Manager.

    Args:
        secret_name (str): Le nom du secret.
        secret_value (str): La valeur du secret.
    """
    secrets_client = get_boto3_client('secretsmanager')
    secrets_client.put_secret_value(SecretId=secret_name, SecretString=secret_value)


def delete_secret(secret_name):
    """Supprime un secret d'AWS Secrets Manager.

    Args:
        secret_name (str): Le nom du secret à supprimer.
    """
    secrets_client = get_boto3_client('secretsmanager')
    secrets_client.delete_secret(SecretId=secret_name)
    print(f"Secret {secret_name} deleted")


#

