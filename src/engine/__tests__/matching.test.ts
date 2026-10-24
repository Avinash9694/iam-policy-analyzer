import {
  actionMatches,
  actionPatternsMayOverlap,
  globToRegExp,
  resourceCovers,
  resourcesCover,
  splitAction,
} from '../matching';

describe('matching', () => {
  it('matches IAM action globs case-insensitively', () => {
    expect(actionMatches('*', 'iam:CreateUser')).toBe(true);
    expect(actionMatches('iam:*', 'iam:CreateUser')).toBe(true);
    expect(actionMatches('iam:Put*', 'iam:PutUserPolicy')).toBe(true);
    expect(actionMatches('iam:put*', 'iam:PutUserPolicy')).toBe(true);
    expect(actionMatches('iam:Put*', 'iam:AttachUserPolicy')).toBe(false);
    expect(actionMatches('s3:Get?bject', 's3:GetObject')).toBe(true);
    expect(actionMatches('s3:GetObject', 's3:GetObjectAcl')).toBe(false);
  });

  it('escapes regex metacharacters in patterns', () => {
    expect(globToRegExp('a.b').test('axb')).toBe(false);
    expect(globToRegExp('a+b(c)').test('a+b(c)')).toBe(true);
  });

  it('splits actions into service and name', () => {
    expect(splitAction('S3:GetObject')).toEqual({ service: 's3', name: 'GetObject' });
    expect(splitAction('nocolon')).toBeUndefined();
    expect(splitAction('s3:')).toBeUndefined();
  });

  it('decides whether one resource pattern covers another', () => {
    expect(resourceCovers('*', 'arn:aws:s3:::b/*')).toBe(true);
    expect(resourceCovers('arn:aws:s3:::b/*', 'arn:aws:s3:::b/x.txt')).toBe(true);
    expect(resourceCovers('arn:aws:s3:::b/*', 'arn:aws:s3:::b/sub/*')).toBe(true);
    expect(resourceCovers('arn:aws:s3:::b/*', 'arn:aws:s3:::other/*')).toBe(false);
    expect(resourceCovers('arn:aws:s3:::b/x.txt', 'arn:aws:s3:::b/*')).toBe(false);
    expect(resourceCovers('arn:aws:s3:::*/logs', 'arn:aws:s3:::b/*')).toBe(false);
    expect(resourceCovers('arn:aws:ec2:*:*:instance/*', 'arn:aws:ec2:*:*:instance/i-1')).toBe(true);
    expect(resourceCovers('arn:aws:ec2:*:*:instance/*', 'arn:aws:ec2:*:*:volume/*')).toBe(false);
    expect(resourceCovers('arn:aws:ec2:eu-west-1:*:instance/*', 'arn:aws:ec2:*:*:instance/*')).toBe(
      false,
    );
  });

  it('decides whether two action patterns may overlap', () => {
    expect(actionPatternsMayOverlap('s3:*', 'iam:*')).toBe(false);
    expect(actionPatternsMayOverlap('iam:Get*', 'iam:*')).toBe(true);
    expect(actionPatternsMayOverlap('iam:Get*', 'iam:PutUserPolicy')).toBe(false);
    expect(actionPatternsMayOverlap('*', 'iam:PutUserPolicy')).toBe(true);
    expect(actionPatternsMayOverlap('s3:GetObject', 's3:Get*')).toBe(true);
  });

  it('covers a set only when every narrow pattern is covered', () => {
    expect(resourcesCover(['*'], ['a', 'b'])).toBe(true);
    expect(resourcesCover(['arn:x:a'], ['arn:x:a', 'arn:x:b'])).toBe(false);
    expect(resourcesCover(['arn:x:a', 'arn:x:b*'], ['arn:x:a', 'arn:x:bc'])).toBe(true);
    expect(resourcesCover(['arn:x'], [])).toBe(false);
    expect(resourcesCover(['*'], [])).toBe(true);
  });
});
