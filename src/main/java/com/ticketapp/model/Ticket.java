package com.ticketapp.model;

import java.time.Instant;

/** A support ticket. */
public class Ticket {

    public enum Status { OPEN, ASSIGNED, IN_PROGRESS, RESOLVED, CLOSED }

    private long id;
    private long ownerId;          // CWE-639: used for ownership checks
    private Long assigneeId;       // null = unassigned (CWE-367)
    private String title;          // CWE-117: sanitize before logging
    private String description;    // CWE-770: length-capped
    private String contactInfo;    // CWE-312/359: encrypted at rest, hidden from other users
    private Status status = Status.OPEN;
    private Instant createdAt;
    private long version;          // optimistic-lock column (CWE-820/821)

    public long getId() { return id; }
    public void setId(long id) { this.id = id; }
    public long getOwnerId() { return ownerId; }
    public void setOwnerId(long ownerId) { this.ownerId = ownerId; }
    public Long getAssigneeId() { return assigneeId; }
    public void setAssigneeId(Long assigneeId) { this.assigneeId = assigneeId; }
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public String getContactInfo() { return contactInfo; }
    public void setContactInfo(String contactInfo) { this.contactInfo = contactInfo; }
    public Status getStatus() { return status; }
    public void setStatus(Status status) { this.status = status; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public long getVersion() { return version; }
    public void setVersion(long version) { this.version = version; }
}
