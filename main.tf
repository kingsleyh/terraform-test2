provider "aws" {
  access_key = ""              # Define a provider
  secret_key = ""
  region     = "${var.region}"
}

# Only new terraform cli
terraform {
  required_version = "> 0.11.0"
}

# Set keypair (using a local pub key)
resource "aws_key_pair" "sushi" {
  key_name   = "sushi-key"
  public_key = "${file(var.ssh_pubkey_file)}"
}

# Define a VPC
resource "aws_vpc" "sushi_vpc" {
  cidr_block           = "192.168.0.0/16"
  enable_dns_hostnames = true

  tags {
    Name = "sushiVPC"
  }
}

# Define a gateway
resource "aws_internet_gateway" "sushi_gateway" {
  vpc_id = "${aws_vpc.sushi_vpc.id}"

  tags {
    Name = "sushiGateway"
  }
}

# ------------------------------------- public subnet ------------------------
# Define a public Subnet
resource "aws_subnet" "public_subnet" {
  vpc_id                  = "${aws_vpc.sushi_vpc.id}"
  cidr_block              = "192.168.10.0/24"
  availability_zone       = "${var.availability_zone}"
  map_public_ip_on_launch = true

  tags {
    Name = "publicSubnet"
  }
}

# Routing table for public subnet
resource "aws_route_table" "public_subnet_routing_table" {
  vpc_id = "${aws_vpc.sushi_vpc.id}"

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_internet_gateway.sushi_gateway.id}"
  }

  tags {
    Name = "publicSubnetRoutingTable"
  }
}

# Associate the routing table to the public subnet
resource "aws_route_table_association" "public_subnet_routing_table_assoc" {
  subnet_id      = "${aws_subnet.public_subnet.id}"
  route_table_id = "${aws_route_table.public_subnet_routing_table.id}"
}

# ------------------------------------- private subnet ------------------------
# Define a private Subnet
# resource "aws_subnet" "private_subnet" {
#   vpc_id                  = "${aws_vpc.sushi_vpc.id}"
#   cidr_block              = "192.168.1.0/24"
#   availability_zone       = "${var.availability_zone}"
#   map_public_ip_on_launch = true
#
#   tags {
#     Name = "privateSubnet"
#   }
# }
#
# # Routing table for private subnet
# resource "aws_route_table" "private_subnet_routing_table" {
#   vpc_id = "${aws_vpc.sushi_vpc.id}"
#
#   route {
#     cidr_block = "0.0.0.0/0"
#     gateway_id = "${aws_internet_gateway.sushi_gateway.id}"
#   }
#
#   tags {
#     Name = "privateSubnetRoutingTable"
#   }
# }
#
# # Associate the routing table to the private subnet
# resource "aws_route_table_association" "private_subnet_routing_table_assoc" {
#   subnet_id      = "${aws_subnet.private_subnet.id}"
#   route_table_id = "${aws_route_table.private_subnet_routing_table.id}"
# }

# ------------------------------------- security groups ------------------------
# Define a security group for the ELB
resource "aws_security_group" "load_balancers" {
  name        = "load_balancers"
  description = "Allows all traffic"
  vpc_id      = "${aws_vpc.sushi_vpc.id}"

  # TODO: do we need to allow ingress besides TCP 80 and 443?
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # TODO: this probably only needs egress to the ECS security group.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Define a security group for the ECS
resource "aws_security_group" "ecs" {
  name        = "ecs"
  description = "Allows all traffic"
  vpc_id      = "${aws_vpc.sushi_vpc.id}"

  # TODO: remove this and replace with a bastion host for SSHing into
  # individual machines.
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    security_groups = ["${aws_security_group.load_balancers.id}"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ------------------------------------- ECS Cluster  ------------------------
resource "aws_ecs_cluster" "sushi_cluster" {
  name = "${var.ecs_cluster_name}"
}

# ------------------------------------- Auto scaling group for ECS ------------------------
resource "aws_autoscaling_group" "ecs_cluster" {
  availability_zones   = ["${var.availability_zone}"]
  name                 = "ECS ${var.ecs_cluster_name}"
  min_size             = "${var.autoscale_min}"
  max_size             = "${var.autoscale_max}"
  desired_capacity     = "${var.autoscale_desired}"
  health_check_type    = "EC2"
  launch_configuration = "${aws_launch_configuration.sushi_ecs.name}"
  vpc_zone_identifier  = ["${aws_subnet.public_subnet.id}"]
}

# ------------------------------------- Launch configuration for ECS  ------------------------
resource "aws_launch_configuration" "sushi_ecs" {
  name                        = "ECS ${var.ecs_cluster_name}"
  image_id                    = "${lookup(var.amis, var.region)}"
  instance_type               = "${var.instance_type}"
  security_groups             = ["${aws_security_group.ecs.id}"]
  iam_instance_profile        = "${aws_iam_instance_profile.ecs.name}"
  key_name                    = "${aws_key_pair.sushi.key_name}"
  associate_public_ip_address = true
  user_data                   = "#!/bin/bash\necho ECS_CLUSTER='${var.ecs_cluster_name}' > /etc/ecs/ecs.config"
}

# ------------------------------------- IAM roles  ------------------------
resource "aws_iam_role" "ecs_host_role" {
  name               = "ecs_host_role"
  assume_role_policy = "${file("policies/ecs-role.json")}"
}

resource "aws_iam_role_policy" "ecs_instance_role_policy" {
  name   = "ecs_instance_role_policy"
  policy = "${file("policies/ecs-instance-role-policy.json")}"
  role   = "${aws_iam_role.ecs_host_role.id}"
}

resource "aws_iam_role" "ecs_service_role" {
  name               = "ecs_service_role"
  assume_role_policy = "${file("policies/ecs-role.json")}"
}

resource "aws_iam_role_policy" "ecs_service_role_policy" {
  name   = "ecs_service_role_policy"
  policy = "${file("policies/ecs-service-role-policy.json")}"
  role   = "${aws_iam_role.ecs_service_role.id}"
}

resource "aws_iam_instance_profile" "ecs" {
  name = "ecs-instance-profile"
  path = "/"
  role = "${aws_iam_role.ecs_host_role.name}"
}
