resource "aws_s3_bucket" "example" {
  bucket = "my-test-bucket"

  # Missing encryption configuration - should trigger security findings
}

resource "aws_instance" "example" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  # Missing monitoring and IMDSv2 - should trigger findings
}

resource "aws_security_group" "example" {
  name        = "example-sg"
  description = "Example security group"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # Overly permissive - should trigger findings
  }
}
