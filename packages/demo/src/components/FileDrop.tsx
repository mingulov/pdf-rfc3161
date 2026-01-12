import React, { useState, useRef } from "react";
import { FileUp } from "lucide-react";

interface FileDropProps {
    onFileSelect: (file: File) => void;
    accept?: string;
    label?: string;
    description?: string;
    "data-testid"?: string;
}

export default function FileDrop({
    onFileSelect,
    accept = ".pdf",
    label,
    description,
    "data-testid": testId,
}: FileDropProps) {
    const [isDragging, setIsDragging] = useState(false);
    const fileInputRef = useRef<HTMLInputElement>(null);

    const handleDragOver = (e: React.DragEvent) => {
        e.preventDefault();
        setIsDragging(true);
    };

    const handleDragLeave = () => {
        setIsDragging(false);
    };

    const handleDrop = (e: React.DragEvent) => {
        e.preventDefault();
        setIsDragging(false);
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
            onFileSelect(e.dataTransfer.files[0]);
        }
    };

    return (
        <div
            className={`drop ${isDragging ? "drag" : ""}`}
            role="button"
            tabIndex={0}
            data-testid={testId}
            aria-label={label || "Upload file area. Drop a PDF here or click to browse."}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    fileInputRef.current?.click();
                }
            }}
        >
            <input
                type="file"
                ref={fileInputRef}
                style={{ display: "none" }}
                accept={accept}
                aria-label={label || "Select PDF file to upload"}
                onChange={(e) => {
                    if (e.target.files && e.target.files.length > 0) {
                        onFileSelect(e.target.files[0]);
                    }
                }}
            />
            <FileUp size={48} color="var(--gray)" aria-hidden="true" />
            <h2>{label || "Drop PDF here or click to upload"}</h2>
            <p className="desc">{description || "Supports .pdf files only"}</p>
        </div>
    );
}
